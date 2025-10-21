import json
from typing import Any, Dict, List, Tuple
import subprocess
import os
import tempfile


class ClmmDecoder:
    """IDL on-chain fetch, offsets inference y decodificación con Anchor CLI."""

    def __init__(self, idl: Dict[str, Any]):
        if not isinstance(idl, dict):
            raise ValueError("IDL inválido o no cargado")
        self.idl = idl

    @staticmethod
    def fetch_idl_onchain(program_id: str, cluster: str, wallet_path: str) -> Dict[str, Any]:
        cmd = [
            "/root/.cargo/bin/anchor",
            "idl",
            "fetch",
            program_id,
            "--provider.cluster",
            "mainnet" if cluster == "mainnet-beta" else cluster,
            "--provider.wallet",
            os.path.expanduser(wallet_path),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"anchor idl fetch failed: {proc.stderr or proc.stdout}")
        return json.loads(proc.stdout)

    def _find_position_struct_in_types(self) -> Tuple[str, Dict[str, Any]]:
        types = self.idl.get("types", []) or []
        for td in types:
            if td.get("name") == "PersonalPositionState" and (td.get("type") or {}).get("kind") == "struct":
                return td.get("name"), td
        for td in types:
            name = td.get("name", "")
            t = td.get("type") or {}
            if "position" in name.lower() and t.get("kind") == "struct":
                return name, td
        raise RuntimeError("No se encontró un struct de posición en types del IDL")

    def _sizeof_primitive(self, t: str) -> int:
        mapping = {
            "bool": 1, "u8": 1, "i8": 1,
            "u16": 2, "i16": 2,
            "u32": 4, "i32": 4, "f32": 4,
            "u64": 8, "i64": 8, "f64": 8,
            "u128": 16, "i128": 16,
            "u256": 32, "i256": 32,
            "pubkey": 32, "publicKey": 32,
        }
        if t not in mapping:
            raise ValueError(f"Tipo primitivo no soportado: {t}")
        return mapping[t]

    def _resolve_defined_type(self, name_or_dict: Any) -> Dict[str, Any]:
        name = name_or_dict.get("name") if isinstance(name_or_dict, dict) else name_or_dict
        for td in (self.idl.get("types", []) or []):
            if td.get("name") == name:
                return td.get("type") or {}
        raise ValueError(f"Tipo definido no encontrado en IDL: {name_or_dict}")

    def _sizeof_type(self, t: Any) -> int:
        if isinstance(t, str):
            return self._sizeof_primitive(t)
        if isinstance(t, dict):
            if "array" in t:
                elem_t, length = t["array"][0], int(t["array"][1])
                return length * self._sizeof_type(elem_t)
            if "defined" in t:
                defined = self._resolve_defined_type(t["defined"])
                if defined.get("kind") != "struct":
                    raise ValueError("Solo se soporta 'defined' struct para offsets")
                return sum(self._sizeof_type(f.get("type")) for f in (defined.get("fields") or []))
        raise ValueError(f"Tipo no soportado: {t}")

    def compute_field_offsets_from_type_struct(self, type_def: Dict[str, Any]) -> Dict[str, int]:
        if (type_def.get("kind") != "struct"):
            raise ValueError("El tipo de posición no es un struct")
        offsets: Dict[str, int] = {}
        running = 0
        for field in (type_def.get("fields") or []):
            offsets[field.get("name")] = running
            running += self._sizeof_type(field.get("type"))
        return offsets

    def infer_position_offsets(self) -> Tuple[str, int, int]:
        acc_name, type_entry = self._find_position_struct_in_types()
        offsets = self.compute_field_offsets_from_type_struct(type_entry.get("type") or {})
        pool_offset = 8 + offsets.get("pool_id")
        nft_mint_offset = 8 + offsets.get("nft_mint")
        if pool_offset is None or nft_mint_offset is None:
            raise RuntimeError("Faltan campos 'pool_id' o 'nft_mint' en la posición")
        return acc_name, pool_offset, nft_mint_offset

    def anchor_cli_decode(self, program_id: str, account_type: str, account_pubkey: str, cluster: str, wallet_path: str) -> Dict[str, Any]:
        program_name = ((self.idl.get("metadata") or {}).get("name") if isinstance(self.idl.get("metadata"), dict) else None) or self.idl.get("name") or "program"
        account_type_full = f"{program_name}.{account_type}"
        with tempfile.NamedTemporaryFile("w", delete=False, suffix="-idl.json") as tf:
            tmp_idl_path = tf.name
            json.dump(self.idl, tf)
        try:
            cmd = [
                "/root/.cargo/bin/anchor", "account", account_type_full, account_pubkey,
                "--idl", os.path.abspath(tmp_idl_path),
                "--provider.cluster", ("mainnet" if cluster == "mainnet-beta" else cluster),
                "--provider.wallet", os.path.expanduser(wallet_path),
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                raise RuntimeError(f"anchor account failed: {proc.stderr or proc.stdout}")
            return json.loads(proc.stdout.strip())
        finally:
            try:
                os.unlink(tmp_idl_path)
            except Exception:
                pass

    # ---------------------- IDL inspection helpers ----------------------
    def list_instructions(self) -> List[Dict[str, Any]]:
        """Devuelve un resumen de instrucciones del IDL: nombre y cuentas requeridas.
        Formato: [{name, accounts:[{name, isMut, isSigner, pda?}] }]
        """
        out: List[Dict[str, Any]] = []
        for ix in (self.idl.get("instructions") or []):
            try:
                name = ix.get("name")
                accs_in = ix.get("accounts") or []
                accs_out: List[Dict[str, Any]] = []
                for a in accs_in:
                    acc_item = {
                        "name": a.get("name"),
                        "isMut": bool(a.get("isMut")),
                        "isSigner": bool(a.get("isSigner")),
                    }
                    # PDAs (si están definidas en el IDL)
                    pda = a.get("pda") or {}
                    if pda:
                        acc_item["pda"] = pda
                    accs_out.append(acc_item)
                out.append({"name": name, "accounts": accs_out})
            except Exception:
                continue
        return out

    def get_instruction_schema(self, name: str) -> Dict[str, Any]:
        """Devuelve el objeto de instrucción del IDL (incluye cuentas y args)."""
        for ix in (self.idl.get("instructions") or []):
            if ix.get("name") == name:
                return ix
        raise ValueError(f"Instrucción no encontrada en IDL: {name}")
