import os
import re
import glob
import subprocess
import json
import random
import uuid
from datetime import datetime
from .base_service import BaseService
from app.core.config import (
    HANDSHAKES_DIR,
    BRUCE_HANDSHAKES_DIR,
    BRUCE_PCAP_DIR,
    M5EVIL_HANDSHAKES_DIR,
)
from app.utils.pcap import (
    build_pcap_search_roots,
    resolve_pcap_reference,
)
from app.utils.handshake_artifacts import (
    create_combined_build_id,
    get_capture_artifact_path,
    get_combined_artifact_path,
    get_combined_build_dir,
    resolve_artifact_path,
    write_json,
)
from app.core.job_manager import job_manager
from app.services.history_service import history_service
from app.services import handshake_catalog as handshake_catalog_service


class HashcatService(BaseService):
    def _pcap_search_roots(self):
        return build_pcap_search_roots(
            HANDSHAKES_DIR,
            BRUCE_HANDSHAKES_DIR,
            BRUCE_PCAP_DIR,
            M5EVIL_HANDSHAKES_DIR,
        )

    def _resolve_hash_artifact(
        self,
        filename,
        *,
        capture_id=None,
        combined_build_id=None,
        mac=None,
    ):
        path = resolve_artifact_path(
            filename,
            handshakes_dir=HANDSHAKES_DIR,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
            mac=mac,
        )
        if not path:
            return None
        base_dir = os.path.dirname(path)
        name = os.path.basename(path)
        return {
            "path": path,
            "filename": name,
            "dirname": base_dir,
            "basename": os.path.splitext(name)[0],
            "capture_id": str(capture_id or "") or None,
            "combined_build_id": str(combined_build_id or "") or None,
            "artifact_scope": (
                "combined"
                if combined_build_id
                else ("capture" if capture_id else "shared_legacy")
            ),
        }

    PASSPHRASE_RULE_FILES = ("passphrase-rule1.rule", "passphrase-rule2.rule")
    ATTACK_MODE_POLICIES = {
        "straight": {
            "requires_wordlist": True,
            "supports_increment": False,
            "supports_slow_candidates": True,
        },
        "rules": {
            "requires_wordlist": True,
            "supports_increment": False,
            "supports_slow_candidates": True,
        },
        "passphrase": {
            "requires_wordlist": True,
            "supports_increment": False,
            "supports_slow_candidates": True,
        },
        "association": {
            "requires_wordlist": False,
            "supports_increment": False,
            "supports_slow_candidates": False,
        },
        "association_hint_first": {
            "requires_wordlist": False,
            "supports_increment": False,
            "supports_slow_candidates": False,
        },
        "association_hint_rule": {
            "requires_wordlist": False,
            "supports_increment": False,
            "supports_slow_candidates": True,
        },
        "combinator": {
            "requires_wordlist": True,
            "supports_increment": False,
            "supports_slow_candidates": True,
        },
        "combinator_passphrase": {
            "requires_wordlist": True,
            "supports_increment": False,
            "supports_slow_candidates": True,
        },
        "digits": {
            "requires_wordlist": False,
            "supports_increment": True,
            "supports_slow_candidates": False,
        },
        "mask": {
            "requires_wordlist": False,
            "supports_increment": True,
            "supports_slow_candidates": False,
        },
        "mask_profile": {
            "requires_wordlist": False,
            "supports_increment": False,
            "supports_slow_candidates": False,
        },
        "hybrid": {
            "requires_wordlist": True,
            "supports_increment": False,
            "supports_slow_candidates": True,
        },
        "hybrid_reverse": {
            "requires_wordlist": True,
            "supports_increment": False,
            "supports_slow_candidates": True,
        },
        "hybrid_mask_profile": {
            "requires_wordlist": True,
            "supports_increment": False,
            "supports_slow_candidates": True,
        },
        "hybrid_reverse_mask_profile": {
            "requires_wordlist": True,
            "supports_increment": False,
            "supports_slow_candidates": True,
        },
    }
    ASSOCIATION_CANDIDATE_CAPS = {
        "association": 20000,
        "association_hint_first": 60000,
        "association_hint_rule": 60000,
    }
    ASSOCIATION_SUFFIXES = ("123", "2024", "2025", "2026")
    ASSOCIATION_PREVIEW_SAMPLE = 12

    FUNNY_MULTI_WORDS = [
        "pwn",
        "ward",
        "sniff",
        "beacon",
        "handshake",
        "cap",
        "probe",
        "deauth",
        "bssid",
        "ssid",
        "packet",
        "channel",
        "radio",
        "antenna",
        "survey",
        "loot",
        "capture",
        "recon",
        "wardriver",
        "wigle",
        "tracker",
        "stalker",
        "wardrive",
        "pwnagotchi",
    ]
    CARIOCA_SLANG = [
        "mane",
        "parca",
        "moleque",
        "bolado",
        "brabo",
        "sinistro",
        "papo",
        "fechamento",
        "bond",
        "mermao",
        "to_suave",
        "coisa_louca",
        "sangue_bom",
        "boladao",
        "pilantra",
        "malandro",
        "resenha",
        "firmeza",
        "se_liga",
        "qualfoi",
        "vapo",
        "ainda",
        "tudo_certo",
        "de_boa",
        "suave_na_nave",
        "na_moral",
        "da_hora",
        "show_de_bola",
        "massa",
        "irado",
        "fera",
        "top",
        "zica",
        "da_porra",
        "cabuloso",
        "sinistro",
        "e_nois",
        "tamo_junto",
        "flw",
        "brabao",
        "mec",
        "meczada",
    ]

    def _generate_funny_multi_name(self):
        for _ in range(20):
            tech = random.choice(self.FUNNY_MULTI_WORDS)
            slang = random.choice(self.CARIOCA_SLANG)
            w1, w2 = random.sample([tech, slang], 2)
            num = random.randint(10, 99)
            filename = f"batch_{w1}_{w2}_{num}.22000"
            batch_path = os.path.join(HANDSHAKES_DIR, filename)
            manifest_path = os.path.join(HANDSHAKES_DIR, f"{filename}.batch.json")
            if not os.path.exists(batch_path) and not os.path.exists(manifest_path):
                return filename
        # fallback if collisions persist
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rand = random.randint(1000, 9999)
        return f"batch_{timestamp}_{rand}.22000"

    def _get_attack_mode_policy(self, attack_mode):
        return self.ATTACK_MODE_POLICIES.get(
            attack_mode, self.ATTACK_MODE_POLICIES["straight"]
        )

    def _requires_wordlist(self, attack_mode):
        return self._get_attack_mode_policy(attack_mode)["requires_wordlist"]

    def _supports_increment(self, attack_mode):
        return self._get_attack_mode_policy(attack_mode)["supports_increment"]

    def _supports_slow_candidates(self, attack_mode):
        return self._get_attack_mode_policy(attack_mode)["supports_slow_candidates"]

    def get_available_rules(self):
        """Lista arquivos .rule disponíveis no diretório de regras do hashcat (se configurado) ou local"""
        rules = []
        try:
            conf = self._get_config()
            hashcat_bin = conf.get("hashcat_path", "hashcat")
            custom_rules_dir = conf.get("custom_rules_path", "")

            # 1. Regras padrão do Hashcat
            base_dir = (
                os.path.dirname(hashcat_bin) if os.path.isabs(hashcat_bin) else "."
            )
            rules_dir = os.path.join(base_dir, "rules")

            if os.path.exists(rules_dir):
                for f in glob.glob(os.path.join(rules_dir, "*.rule")):
                    rules.append({"name": os.path.basename(f), "path": f})

            # 2. Regras Customizadas
            if custom_rules_dir and os.path.exists(custom_rules_dir):
                for f in glob.glob(os.path.join(custom_rules_dir, "*.rule")):
                    # Evita duplicatas se o nome for igual
                    name = os.path.basename(f)
                    if not any(r["name"] == name for r in rules):
                        rules.append({"name": name, "path": f})

            if not rules:
                rules.append({"name": "best64.rule", "path": "rules/best64.rule"})

            return sorted(rules, key=lambda x: x["name"])
        except Exception as e:
            self.logger.error(f"Erro ao listar regras: {e}")
            return [{"name": "best64.rule", "path": "rules/best64.rule"}]

    def get_available_masks(self):
        """Lista arquivos .hcmask disponíveis no diretório de masks do hashcat e custom."""
        masks = []
        try:
            conf = self._get_config()
            hashcat_bin = conf.get("hashcat_path", "hashcat")
            custom_masks_dir = conf.get("custom_masks_path", "")

            base_dir = (
                os.path.dirname(hashcat_bin) if os.path.isabs(hashcat_bin) else "."
            )
            masks_dir = os.path.join(base_dir, "masks")

            if os.path.exists(masks_dir):
                for f in glob.glob(os.path.join(masks_dir, "*.hcmask")):
                    masks.append({"name": os.path.basename(f), "path": f})

            if custom_masks_dir and os.path.exists(custom_masks_dir):
                for f in glob.glob(os.path.join(custom_masks_dir, "*.hcmask")):
                    name = os.path.basename(f)
                    if not any(m["name"] == name for m in masks):
                        masks.append({"name": name, "path": f})

            return sorted(masks, key=lambda x: x["name"])
        except Exception as e:
            self.logger.error(f"Erro ao listar masks: {e}")
            return []

    def get_devices(self):
        """Lista dispositivos disponíveis usando hashcat -I, incluindo o backend (Metal, OpenCL, etc)."""
        devices = []
        try:
            conf = self._get_config()
            hashcat_bin = conf.get("hashcat_path", "hashcat")
            use_wsl = self._should_use_wsl(hashcat_bin)

            cwd = None
            if os.path.isabs(hashcat_bin) and not use_wsl:
                cwd = os.path.dirname(hashcat_bin)

            cmd = []
            if use_wsl:
                cmd = ["wsl", hashcat_bin, "-I"]
            else:
                cmd = [hashcat_bin, "-I"]

            result = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
            )

            if result.returncode == 0:
                current_device = None
                current_backend = "N/A"
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if not line:
                        continue

                    # Detect backend section header, e.g., "Metal Info:", "OpenCL Info:"
                    if line.endswith(" Info:"):
                        current_backend = line.replace(" Info:", "").strip()
                        continue

                    # Universal check for the start of a new device block
                    match = re.search(r"Backend Device ID\s*[:#]\s*(\d+)", line)
                    if match:
                        if current_device:
                            devices.append(current_device)

                        device_id = match.group(1)
                        # Initialize device with backend info
                        current_device = {
                            "id": device_id,
                            "name": f"Device #{device_id}",
                            "type": "N/A",
                            "backend": current_backend,
                        }

                    elif current_device and ":" in line:
                        key_part, value_part = line.split(":", 1)
                        # Chave normalizada: remove pontos, espaços e converte para minúsculas
                        key = key_part.strip().replace(".", "").lower()
                        value = value_part.strip()

                        if key == "name":
                            current_device["name"] = value
                        elif key == "type":
                            current_device["type"] = value

                if current_device:
                    devices.append(current_device)

            return devices
        except Exception as e:
            self.logger.error(f"Erro ao listar dispositivos: {e}")
            return []

    def _resolve_passphrase_rule_paths(
        self, rule_file, wordlist, hashcat_bin, custom_rules_dir
    ):
        """Resolve as duas rules do modo passphrase.

        Suporta:
        - `rule_file` com dois caminhos separados por vírgula/; (rule1,rule2)
        - auto-descoberta em diretórios comuns (wordlist, custom_rules_path, rules/)
        """
        explicit_rules = []
        if rule_file:
            explicit_rules = [
                part.strip()
                for part in re.split(r"[;,]", str(rule_file))
                if part.strip()
            ]

        if len(explicit_rules) == 2:
            missing = [p for p in explicit_rules if not os.path.exists(p)]
            if missing:
                return None, None, f"Passphrase rules not found: {', '.join(missing)}"
            return explicit_rules[0], explicit_rules[1], None

        candidate_dirs = []
        if len(explicit_rules) == 1:
            hinted = explicit_rules[0]
            if os.path.isdir(hinted):
                candidate_dirs.append(hinted)
            else:
                candidate_dirs.append(os.path.dirname(hinted))

        if wordlist:
            candidate_dirs.append(
                wordlist if os.path.isdir(wordlist) else os.path.dirname(wordlist)
            )

        if custom_rules_dir:
            candidate_dirs.append(custom_rules_dir)

        base_dir = os.path.dirname(hashcat_bin) if os.path.isabs(hashcat_bin) else "."
        candidate_dirs.append(os.path.join(base_dir, "rules"))
        candidate_dirs.append("rules")
        candidate_dirs.append(".")

        deduped_dirs = []
        seen = set()
        for directory in candidate_dirs:
            if not directory:
                continue
            norm = os.path.abspath(directory)
            if norm in seen:
                continue
            seen.add(norm)
            deduped_dirs.append(directory)

        rule1_name, rule2_name = self.PASSPHRASE_RULE_FILES
        for directory in deduped_dirs:
            rule1 = os.path.join(directory, rule1_name)
            rule2 = os.path.join(directory, rule2_name)
            if os.path.exists(rule1) and os.path.exists(rule2):
                return rule1, rule2, None

        searched = ", ".join(deduped_dirs)
        return (
            None,
            None,
            f"Passphrase mode requires {rule1_name} and {rule2_name}. Searched: {searched}",
        )

    def _normalize_association_seed(self, value):
        if value is None:
            return ""
        text = str(value)
        clean = "".join(ch for ch in text if ch.isprintable())
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean

    def _extract_essids_from_hash_lines(self, lines):
        essids = []
        seen = set()
        for line in lines:
            try:
                parts = line.split("*")
                if len(parts) <= 5 or not parts[0].upper().startswith("WPA"):
                    continue
                essid_hex = parts[5]
                decoded = bytes.fromhex(essid_hex).decode("utf-8", errors="replace")
                normalized = self._normalize_association_seed(decoded)
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    essids.append(normalized)
            except Exception:
                continue
        return essids

    def _association_variant_candidates(self, seed):
        normalized = self._normalize_association_seed(seed)
        if not normalized:
            return []

        candidates = []
        seen = set()

        def add(value):
            cleaned = self._normalize_association_seed(value)
            if not cleaned or cleaned in seen:
                return
            seen.add(cleaned)
            candidates.append(cleaned)

        add(normalized)
        add(normalized.lower())
        add(normalized.upper())

        compact = re.sub(r"[\s_.-]+", "", normalized)
        if compact:
            add(compact)
            add(compact.lower())
            add(compact.upper())

        base_for_suffix = list(candidates)
        for base in base_for_suffix:
            for suffix in self.ASSOCIATION_SUFFIXES:
                add(f"{base}{suffix}")

        return candidates

    def _build_association_candidates_v2(
        self,
        hash_path,
        mode="association",
        association_hint=None,
        association_hints=None,
        preview_sample_size=None,
    ):
        if not os.path.exists(hash_path):
            return {"status": "error", "message": "Hash file not found"}

        with open(hash_path, "r", encoding="utf-8", errors="replace") as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]

        if not lines:
            return {"status": "error", "message": "Hash file is empty"}

        valid_modes = {"association", "association_hint_first"}
        if mode not in valid_modes:
            return {
                "status": "error",
                "message": f"Invalid association mode: {mode}",
            }

        ssid_values = self._extract_essids_from_hash_lines(lines)
        hint_values = []
        if mode == "association":
            one_hint = self._normalize_association_seed(association_hint)
            if one_hint:
                hint_values.append(one_hint)
        else:
            raw = str(association_hints or "")
            for line in raw.splitlines():
                hint = self._normalize_association_seed(line)
                if hint and hint not in hint_values:
                    hint_values.append(hint)

        seed_entries = []
        if mode == "association":
            for ssid in ssid_values:
                seed_entries.append(("ssid", ssid))
            for hint in hint_values:
                seed_entries.append(("fallback_hint", hint))
        else:
            for hint in hint_values:
                seed_entries.append(("hint", hint))
            for ssid in ssid_values:
                seed_entries.append(("ssid_fallback", ssid))

        if not seed_entries:
            if mode == "association_hint_first":
                return {
                    "status": "error",
                    "message": "Hint-first mode requires hints or SSID extracted from hash.",
                }
            return {
                "status": "error",
                "message": "Association mode requires SSID in hash or fallback hint.",
            }

        cap = self.ASSOCIATION_CANDIDATE_CAPS.get(mode, 20000)
        candidates = []
        seen = set()
        transformations_used = set()
        capped = False
        source_seed_count = {
            "ssid": 0,
            "hint": 0,
            "fallback_hint": 0,
            "ssid_fallback": 0,
        }

        for source, seed in seed_entries:
            source_seed_count[source] = source_seed_count.get(source, 0) + 1
            variants = self._association_variant_candidates(seed)
            for variant in variants:
                normalized = self._normalize_association_seed(variant)
                if not normalized or normalized in seen:
                    continue
                seen.add(normalized)
                candidates.append(normalized)
                if normalized == seed:
                    transformations_used.add("original")
                elif normalized.lower() == seed.lower():
                    transformations_used.add("case_variants")
                elif re.sub(r"[\s_.-]+", "", seed) == normalized:
                    transformations_used.add("strip_separators")
                elif any(normalized.endswith(s) for s in self.ASSOCIATION_SUFFIXES):
                    transformations_used.add("common_suffixes")
                if len(candidates) >= cap:
                    capped = True
                    break
            if capped:
                break

        if not candidates:
            return {
                "status": "error",
                "message": "No association candidates generated.",
            }

        warnings = []
        if capped:
            warnings.append(f"Candidate list capped at {cap} entries.")
        if not ssid_values:
            warnings.append("No SSID extracted from hash lines; relying on hints only.")
        if mode == "association_hint_first" and not hint_values:
            warnings.append("No user hints provided; using SSID fallback only.")

        sample_size = (
            preview_sample_size
            if isinstance(preview_sample_size, int) and preview_sample_size > 0
            else self.ASSOCIATION_PREVIEW_SAMPLE
        )

        return {
            "status": "success",
            "mode": mode,
            "candidates": candidates,
            "candidate_count": len(candidates),
            "capped": capped,
            "cap": cap,
            "sample_candidates": candidates[:sample_size],
            "sources": {
                "seed_counts": source_seed_count,
                "ssid_count": len(ssid_values),
                "hint_count": len(hint_values),
                "transformations": sorted(transformations_used),
            },
            "warnings": warnings,
        }

    def _write_association_candidates_file(self, hash_path, candidates):
        assoc_filename = (
            f"association_{os.path.basename(hash_path)}_{uuid.uuid4().hex[:8]}.txt"
        )
        assoc_path = os.path.join(HANDSHAKES_DIR, assoc_filename)
        with open(assoc_path, "w", encoding="utf-8") as af:
            af.write("\n".join(candidates))
            af.write("\n")
        return assoc_path

    def preview_association_candidates(
        self,
        hash_filename,
        mode="association",
        association_hint=None,
        association_hints=None,
        capture_id=None,
        combined_build_id=None,
        mac=None,
    ):
        resolved_hash = self._resolve_hash_artifact(
            hash_filename,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
            mac=mac,
        )
        hash_path = resolved_hash.get("path") if resolved_hash else None
        if not hash_path:
            return {"status": "error", "message": "Hash file not found"}
        result = self._build_association_candidates_v2(
            hash_path,
            mode=mode,
            association_hint=association_hint,
            association_hints=association_hints,
            preview_sample_size=self.ASSOCIATION_PREVIEW_SAMPLE,
        )
        if result.get("status") != "success":
            return result

        return {
            "status": "success",
            "mode": result["mode"],
            "candidate_count": result["candidate_count"],
            "capped": result["capped"],
            "cap": result["cap"],
            "sample_candidates": result["sample_candidates"],
            "sources": result["sources"],
            "warnings": result["warnings"],
        }

    def convert_pcap(self, pcap_filename, capture_id=None, raw_item_id=None):
        try:
            conf = self._get_config()
            hcx_bin = conf.get("hcxpcapngtool_path", "hcxpcapngtool")

            resolved = resolve_pcap_reference(
                pcap_filename,
                capture_id=capture_id,
                raw_item_id=raw_item_id,
                search_roots=self._pcap_search_roots(),
            )
            pcap_path = resolved.get("path") if resolved else None
            display_filename = resolved.get("filename") if resolved else pcap_filename
            base_name = (
                resolved.get("basename")
                if resolved
                else str(pcap_filename).rsplit(".", 1)[0]
            )
            output_file = (
                get_capture_artifact_path(
                    capture_id,
                    "22000",
                    handshakes_dir=HANDSHAKES_DIR,
                    ensure_parent=True,
                )
                if capture_id and not raw_item_id
                else os.path.join(HANDSHAKES_DIR, f"{base_name}.22000")
            )

            if not pcap_path or not os.path.exists(pcap_path):
                return {
                    "status": "error",
                    "message": f"PCAP file not found: {pcap_filename}",
                }

            use_wsl = self._should_use_wsl(hcx_bin)
            cwd = None
            command = None

            if use_wsl:
                wsl_pcap = self._to_wsl_path(pcap_path)
                wsl_output = self._to_wsl_path(output_file)
                wsl_hcx_bin = self._to_wsl_path(hcx_bin)
                command = ["wsl", wsl_hcx_bin, "-o", wsl_output, wsl_pcap]
            else:
                if os.path.isabs(hcx_bin):
                    cwd = os.path.dirname(hcx_bin)
                command = [hcx_bin, "-o", output_file, pcap_path]

            self.logger.info(f"Iniciando job de conversão HCX: {command} (CWD: {cwd})")

            entry_id = history_service.add_entry(
                display_filename,
                "hcxpcapngtool",
                command,
                capture_id=capture_id if not raw_item_id else None,
            )

            def on_complete(job):
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    history_service.update_entry(
                        display_filename,
                        entry_id,
                        "SUCCESS",
                        "Converted to .22000",
                        capture_id=capture_id if not raw_item_id else None,
                    )
                    from app.services.data_loader import reload_data

                    reload_data()
                else:
                    meta = []
                    if job.get("logs"):
                        for line in job["logs"]:
                            if (
                                "error" in line.lower()
                                or "failed" in line.lower()
                                or "missing" in line.lower()
                            ):
                                meta.append(line.strip())
                    history_service.update_entry(
                        display_filename,
                        entry_id,
                        "FAILED",
                        "Empty output file",
                        meta,
                        capture_id=capture_id if not raw_item_id else None,
                    )
                    job["status"] = "failed"
                    job["progress_data"]["stage"] = "ERROR"
                    job["progress_data"]["extra"] = "Empty output file"

            def on_start(job):
                history_service.update_entry(
                    display_filename,
                    entry_id,
                    "RUNNING",
                    capture_id=capture_id if not raw_item_id else None,
                )

            job_id = job_manager.start_job(
                command,
                job_type="conversion",
                cwd=cwd,
                on_complete=on_complete,
                on_start=on_start,
            )

            return {
                "status": "started",
                "job_id": job_id,
                "output_file": os.path.basename(output_file),
            }
        except Exception as e:
            self.logger.error(f"Erro ao iniciar conversão HCX: {e}")
            return {"status": "error", "message": str(e)}

    def convert_pcap_now(
        self, pcap_filename, output_filename=None, capture_id=None, raw_item_id=None
    ):
        """Converte um PCAP para .22000 de forma síncrona (sem job manager)."""
        try:
            conf = self._get_config()
            hcx_bin = conf.get("hcxpcapngtool_path", "hcxpcapngtool")
            use_wsl = self._should_use_wsl(hcx_bin)

            resolved = resolve_pcap_reference(
                pcap_filename,
                capture_id=capture_id,
                raw_item_id=raw_item_id,
                search_roots=self._pcap_search_roots(),
            )
            pcap_path = resolved.get("path") if resolved else None
            if not pcap_path or not os.path.exists(pcap_path):
                return {
                    "status": "error",
                    "message": f"PCAP file not found: {pcap_filename}",
                }

            base_name = str(
                (resolved or {}).get("basename")
                or os.path.basename(str(pcap_filename)).rsplit(".", 1)[0]
            )
            target_name = (
                os.path.basename(output_filename)
                if output_filename
                else (
                    os.path.basename(
                        get_capture_artifact_path(
                            capture_id,
                            "22000",
                            handshakes_dir=HANDSHAKES_DIR,
                            ensure_parent=True,
                        )
                    )
                    if capture_id and not raw_item_id
                    else f"{base_name}.22000"
                )
            )
            output_file = (
                (
                    get_capture_artifact_path(
                        capture_id,
                        "22000",
                        handshakes_dir=HANDSHAKES_DIR,
                        ensure_parent=True,
                    )
                    if capture_id and not raw_item_id and not output_filename
                    else os.path.join(HANDSHAKES_DIR, target_name)
                )
                if not os.path.isabs(str(output_filename or ""))
                else str(output_filename)
            )
            tmp_output_file = f"{output_file}.tmp.{uuid.uuid4().hex[:8]}"

            cwd = None
            if use_wsl:
                wsl_hcx_bin = self._to_wsl_path(hcx_bin)
                wsl_output = self._to_wsl_path(tmp_output_file)
                wsl_pcap = self._to_wsl_path(pcap_path)
                command = ["wsl", wsl_hcx_bin, "-o", wsl_output, wsl_pcap]
            else:
                if os.path.isabs(hcx_bin):
                    cwd = os.path.dirname(hcx_bin)
                command = [hcx_bin, "-o", tmp_output_file, pcap_path]

            result = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                check=False,
                encoding="utf-8",
                errors="replace",
            )
            stderr_text = (result.stderr or "").strip()
            stdout_text = (result.stdout or "").strip()
            log_tail = "\n".join(
                [line for line in [stderr_text, stdout_text] if line][:8]
            )

            tmp_ok = (
                os.path.exists(tmp_output_file) and os.path.getsize(tmp_output_file) > 0
            )
            if result.returncode == 0 and tmp_ok:
                os.replace(tmp_output_file, output_file)
                return {
                    "status": "success",
                    "output_file": os.path.basename(output_file),
                }

            if os.path.exists(tmp_output_file):
                try:
                    os.remove(tmp_output_file)
                except Exception:
                    pass

            if result.returncode == 0:
                return {
                    "status": "error",
                    "message": "Conversion finished with empty output.",
                    "log_tail": log_tail,
                }

            return {
                "status": "error",
                "message": f"hcxpcapngtool failed (exit {result.returncode})",
                "log_tail": log_tail,
            }
        except Exception as e:
            self.logger.error(f"Erro em conversão síncrona HCX: {e}")
            return {"status": "error", "message": str(e)}

    def convert_multi_pcap(self, pcap_filenames, capture_ids=None):
        try:
            normalized_filenames = list(pcap_filenames or [])
            normalized_capture_ids = list(capture_ids or [])
            if not normalized_filenames and not normalized_capture_ids:
                return {"status": "error", "message": "No PCAP files provided"}

            conf = self._get_config()
            hcx_bin = conf.get("hcxpcapngtool_path", "hcxpcapngtool")
            use_wsl = self._should_use_wsl(hcx_bin)

            output_filename = self._generate_funny_multi_name()
            output_file = os.path.join(HANDSHAKES_DIR, output_filename)
            manifest_path = os.path.join(
                HANDSHAKES_DIR, f"{output_filename}.batch.json"
            )

            if os.path.exists(output_file):
                self.logger.error(f"Batch output collision: {output_file}")
                return {
                    "status": "error",
                    "message": "Batch output file already exists",
                }
            if os.path.exists(manifest_path):
                self.logger.error(f"Batch manifest collision: {manifest_path}")
                return {"status": "error", "message": "Batch manifest already exists"}

            items = []
            reference_plan = []
            if normalized_capture_ids:
                for capture_id in normalized_capture_ids:
                    reference_plan.append({"filename": None, "capture_id": capture_id})
            for filename in normalized_filenames:
                reference_plan.append({"filename": filename, "capture_id": None})

            total = len(reference_plan)

            def worker(job, emit):
                nonlocal items
                job["progress_data"]["total_steps"] = total

                for idx, reference in enumerate(reference_plan, start=1):
                    pcap_filename = reference.get("filename")
                    capture_id = reference.get("capture_id")
                    resolved = resolve_pcap_reference(
                        pcap_filename,
                        capture_id=capture_id,
                        search_roots=self._pcap_search_roots(),
                    )
                    resolved_filename = (
                        resolved.get("filename")
                        if resolved
                        else str(pcap_filename or capture_id or "")
                    )
                    base_name = str(
                        (resolved or {}).get("basename")
                        or str(resolved_filename).rsplit(".", 1)[0]
                    )
                    parts = base_name.split("_")
                    ssid = "_".join(parts[:-1]) if len(parts) >= 2 else base_name
                    mac_clean = parts[-1] if len(parts) >= 2 else ""
                    item = {
                        "filename": resolved_filename,
                        "ssid": ssid,
                        "mac": mac_clean,
                        "capture_id": capture_id,
                        "status": "QUEUED",
                    }
                    items.append(item)

                    pcap_path = resolved.get("path") if resolved else None
                    if not pcap_path or not os.path.exists(pcap_path):
                        item["status"] = "FAILED"
                        item["reason"] = "PCAP NOT FOUND"
                        job["progress_data"]["current_step"] = idx
                        job["progress_data"]["percentage"] = int((idx / total) * 100)
                        job["progress_data"]["extra"] = f"Missing: {resolved_filename}"
                        job["progress_data"]["items"] = items
                        emit(
                            "job_progress",
                            {"job_id": job["id"], "data": job["progress_data"].copy()},
                        )
                        continue

                    item["status"] = "CONVERTING"
                    job["progress_data"]["current_step"] = idx
                    job["progress_data"]["extra"] = resolved_filename
                    job["progress_data"]["items"] = items
                    emit(
                        "job_progress",
                        {"job_id": job["id"], "data": job["progress_data"].copy()},
                    )

                    temp_out = f"{output_file}.{idx}.tmp"
                    try:
                        if use_wsl:
                            wsl_pcap = self._to_wsl_path(pcap_path)
                            wsl_output = self._to_wsl_path(temp_out)
                            wsl_hcx_bin = self._to_wsl_path(hcx_bin)
                            cmd = ["wsl", wsl_hcx_bin, "-o", wsl_output, wsl_pcap]
                            result = subprocess.run(cmd, capture_output=True, text=True)
                        else:
                            cmd = [hcx_bin, "-o", temp_out, pcap_path]
                            result = subprocess.run(cmd, capture_output=True, text=True)

                        stderr_out = (
                            (result.stderr or "") + "\n" + (result.stdout or "")
                        )
                        reason = None
                        if re.search(r"no\\s+PMKID", stderr_out, re.IGNORECASE):
                            reason = "NO PMKID"
                        elif re.search(
                            r"no\\s+WPA\\s+handshake", stderr_out, re.IGNORECASE
                        ) or re.search(
                            r"no\\s+valid\\s+handshake", stderr_out, re.IGNORECASE
                        ):
                            reason = "NO VALID HANDSHAKE"
                        elif re.search(
                            r"failed", stderr_out, re.IGNORECASE
                        ) and re.search(r"handshake", stderr_out, re.IGNORECASE):
                            reason = "FAILED HANDSHAKE HASH"
                        elif re.search(
                            r"EAPOL", stderr_out, re.IGNORECASE
                        ) and re.search(
                            r"missing|invalid|not\\s+found", stderr_out, re.IGNORECASE
                        ):
                            reason = "EAPOL MISSING/INVALID"
                        elif re.search(
                            r"unsupported|invalid", stderr_out, re.IGNORECASE
                        ):
                            reason = "UNSUPPORTED/INVALID"

                        if (
                            result.returncode == 0
                            and os.path.exists(temp_out)
                            and os.path.getsize(temp_out) > 0
                        ):
                            try:
                                with open(
                                    temp_out, "r", encoding="utf-8", errors="ignore"
                                ) as tf:
                                    hash_lines = [
                                        line.strip()
                                        for line in tf.readlines()
                                        if line.strip()
                                    ]
                                hash_keys = []
                                for h in hash_lines:
                                    parts = h.split("*")
                                    if len(parts) > 5 and parts[0].upper().startswith(
                                        "WPA"
                                    ):
                                        digest = parts[2].lower()
                                        bssid = parts[3].lower()
                                        sta = parts[4].lower()
                                        essid_hex = parts[5]
                                        hash_keys.append(
                                            f"{digest}:{bssid}:{sta}:{essid_hex}"
                                        )
                                item["hash_keys"] = hash_keys
                            except Exception:
                                item["hash_keys"] = []
                            with open(temp_out, "rb") as fin, open(
                                output_file, "ab"
                            ) as fout:
                                fout.write(fin.read())
                            item["status"] = "OK"
                            item["reason"] = "HANDSHAKE OK"
                        else:
                            item["status"] = "FAILED"
                            item["hash_keys"] = []
                            if reason:
                                item["reason"] = reason
                            elif result.returncode == 0:
                                item["reason"] = "EMPTY OUTPUT"
                            else:
                                item["reason"] = "CONVERSION FAILED"
                    except Exception:
                        item["status"] = "FAILED"
                        item["hash_keys"] = []
                        item["reason"] = "CONVERSION ERROR"
                    finally:
                        if os.path.exists(temp_out):
                            try:
                                os.remove(temp_out)
                            except Exception:
                                pass

                    job["progress_data"]["current_step"] = idx
                    job["progress_data"]["percentage"] = int((idx / total) * 100)
                    job["progress_data"]["items"] = items
                    emit(
                        "job_progress",
                        {"job_id": job["id"], "data": job["progress_data"].copy()},
                    )

                # Write manifest
                try:
                    manifest = {
                        "output": output_filename,
                        "created_at": datetime.now().isoformat(),
                        "items": items,
                    }
                    with open(manifest_path, "w", encoding="utf-8") as f:
                        json.dump(manifest, f, indent=2)
                except Exception:
                    pass

            job_id = job_manager.start_multi_job(
                worker,
                job_type="conversion_multi",
                total_steps=total,
                meta={"output_file": output_filename},
            )

            return {
                "status": "started",
                "job_id": job_id,
                "output_file": output_filename,
            }
        except Exception as e:
            self.logger.error(f"Erro ao iniciar conversão multi: {e}")
            return {"status": "error", "message": str(e)}

    def build_combined_candidate(self, mac, capture_ids=None):
        normalized_mac = handshake_catalog_service.normalize_mac(mac)
        if not normalized_mac:
            return {"status": "error", "message": "Invalid MAC / BSSID"}

        handshake_set = handshake_catalog_service.get_handshake_set(normalized_mac)
        if not handshake_set:
            return {"status": "error", "message": "Handshake set not found"}

        available_captures = {
            str(capture.get("capture_id") or ""): capture
            for capture in (handshake_set.get("captures") or [])
            if str(capture.get("capture_id") or "").strip()
        }
        requested_ids = [
            str(item or "").strip()
            for item in (capture_ids or list(available_captures.keys()))
            if str(item or "").strip()
        ]
        requested_ids = [item for item in requested_ids if item in available_captures]
        if not requested_ids:
            return {"status": "error", "message": "No compatible captures selected"}

        build_id = create_combined_build_id(requested_ids)
        build_dir = get_combined_build_dir(
            normalized_mac, build_id, handshakes_dir=HANDSHAKES_DIR, ensure=True
        )
        if not build_dir:
            return {
                "status": "error",
                "message": "Failed to prepare combined build directory",
            }

        output_path = get_combined_artifact_path(
            normalized_mac,
            build_id,
            "22000",
            handshakes_dir=HANDSHAKES_DIR,
            ensure_parent=True,
        )
        manifest_path = get_combined_artifact_path(
            normalized_mac,
            build_id,
            "manifest",
            handshakes_dir=HANDSHAKES_DIR,
            ensure_parent=True,
        )
        if not output_path or not manifest_path:
            return {
                "status": "error",
                "message": "Failed to prepare combined output paths",
            }

        temp_outputs: list[str] = []
        unique_lines: list[str] = []
        seen_lines: set[str] = set()
        included_captures: list[dict] = []

        try:
            for capture_id in requested_ids:
                capture = available_captures[capture_id]
                hash_entries = list(
                    (capture.get("artifacts") or {}).get("hash_22000") or []
                )
                usable_hash = next(
                    (
                        item
                        for item in hash_entries
                        if int(item.get("valid_hash_lines") or 0) > 0
                        and os.path.exists(str(item.get("path") or ""))
                    ),
                    None,
                )
                source_path = None
                source_kind = None
                if usable_hash:
                    source_path = str(usable_hash.get("path") or "")
                    source_kind = "existing_hash"
                else:
                    temp_output = os.path.join(
                        build_dir, f"capture_{capture_id}.tmp.22000"
                    )
                    convert_result = self.convert_pcap_now(
                        None,
                        output_filename=temp_output,
                        capture_id=capture_id,
                    )
                    if convert_result.get("status") != "success":
                        continue
                    source_path = temp_output
                    source_kind = "converted_from_pcap"
                    temp_outputs.append(temp_output)

                if not source_path or not os.path.exists(source_path):
                    continue

                with open(
                    source_path, "r", encoding="utf-8", errors="replace"
                ) as handle:
                    lines = [line.strip() for line in handle if line.strip()]
                valid_lines = [
                    line for line in lines if line.upper().startswith("WPA*")
                ]
                for line in valid_lines:
                    if line in seen_lines:
                        continue
                    seen_lines.add(line)
                    unique_lines.append(line)
                included_captures.append(
                    {
                        "capture_id": capture_id,
                        "source": capture.get("source"),
                        "device_label": capture.get("device_label"),
                        "source_filename": capture.get("source_filename"),
                        "source_kind": source_kind,
                        "valid_hash_lines": len(valid_lines),
                    }
                )

            if not unique_lines:
                return {
                    "status": "error",
                    "message": "No valid .22000 candidates available for the selected captures",
                }

            with open(output_path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(unique_lines))
                handle.write("\n")

            write_json(
                manifest_path,
                {
                    "mac": normalized_mac,
                    "build_id": build_id,
                    "created_at": datetime.now().isoformat(),
                    "included_capture_ids": requested_ids,
                    "included_captures": included_captures,
                    "deduped_hash_count": len(unique_lines),
                },
            )

            return {
                "status": "success",
                "build_id": build_id,
                "output_file": os.path.basename(output_path),
                "output_path": output_path,
                "included_capture_ids": requested_ids,
                "deduped_hash_count": len(unique_lines),
            }
        finally:
            for temp_output in temp_outputs:
                if os.path.exists(temp_output):
                    try:
                        os.remove(temp_output)
                    except OSError:
                        pass

    def _mode_rules_args(self, cmd_args, context):
        cmd_args.extend(["-a", "0"])
        target_rule = context.get("rule_file") or "rules/best64.rule"
        if context["use_wsl"]:
            cmd_args.extend(["-r", self._to_wsl_path(target_rule)])
            cmd_args.append(self._to_wsl_path(context["wordlist"]))
        else:
            cmd_args.extend(["-r", target_rule])
            cmd_args.append(context["wordlist"])
        return None, None

    def _mode_passphrase_args(self, cmd_args, context):
        cmd_args.extend(["-a", "0"])
        pass_rule_1, pass_rule_2, pass_rule_error = self._resolve_passphrase_rule_paths(
            context["rule_file"],
            context["wordlist"],
            context["hashcat_bin"],
            context["custom_rules_dir"],
        )
        if pass_rule_error:
            return None, pass_rule_error

        context["passphrase_rule_1"] = pass_rule_1
        context["passphrase_rule_2"] = pass_rule_2

        if context["use_wsl"]:
            cmd_args.extend(["-r", self._to_wsl_path(pass_rule_1)])
            cmd_args.extend(["-r", self._to_wsl_path(pass_rule_2)])
            cmd_args.append(self._to_wsl_path(context["wordlist"]))
        else:
            cmd_args.extend(["-r", pass_rule_1])
            cmd_args.extend(["-r", pass_rule_2])
            cmd_args.append(context["wordlist"])
        return None, None

    def _mode_digits_args(self, cmd_args, context):
        cmd_args.extend(["-a", "3"])
        mask = context.get("custom_mask") or "?d?d?d?d?d?d?d?d"
        cmd_args.append(mask)
        return None, None

    def _mode_association_args(self, cmd_args, context):
        cmd_args.extend(["-a", "0"])
        build = self._build_association_candidates_v2(
            context["hash_path"],
            mode="association",
            association_hint=context["association_hint"],
            association_hints=context["association_hints"],
        )
        if build.get("status") != "success":
            return None, build.get("message", "Failed to build association candidates")
        association_candidates_file = self._write_association_candidates_file(
            context["hash_path"], build["candidates"]
        )
        context["association_preview"] = build

        if context["use_wsl"]:
            cmd_args.append(self._to_wsl_path(association_candidates_file))
        else:
            cmd_args.append(association_candidates_file)
        return association_candidates_file, None

    def _mode_association_hint_first_args(self, cmd_args, context):
        cmd_args.extend(["-a", "0"])
        build = self._build_association_candidates_v2(
            context["hash_path"],
            mode="association_hint_first",
            association_hint=context["association_hint"],
            association_hints=context["association_hints"],
        )
        if build.get("status") != "success":
            return None, build.get("message", "Failed to build association candidates")
        association_candidates_file = self._write_association_candidates_file(
            context["hash_path"], build["candidates"]
        )
        context["association_preview"] = build

        if context["use_wsl"]:
            cmd_args.append(self._to_wsl_path(association_candidates_file))
        else:
            cmd_args.append(association_candidates_file)
        return association_candidates_file, None

    def _mode_association_hint_rule_args(self, cmd_args, context):
        cmd_args.extend(["-a", "0"])
        build = self._build_association_candidates_v2(
            context["hash_path"],
            mode="association_hint_first",
            association_hint=context["association_hint"],
            association_hints=context["association_hints"],
        )
        if build.get("status") != "success":
            return None, build.get("message", "Failed to build association candidates")
        association_candidates_file = self._write_association_candidates_file(
            context["hash_path"], build["candidates"]
        )
        context["association_preview"] = build

        target_rule = context.get("rule_file") or "rules/best64.rule"
        if context["use_wsl"]:
            cmd_args.extend(["-r", self._to_wsl_path(target_rule)])
            cmd_args.append(self._to_wsl_path(association_candidates_file))
        else:
            cmd_args.extend(["-r", target_rule])
            cmd_args.append(association_candidates_file)
        return association_candidates_file, None

    def _mode_combinator_args(self, cmd_args, context):
        cmd_args.extend(["-a", "1"])

        if context["use_wsl"]:
            cmd_args.append(self._to_wsl_path(context["wordlist"]))
        else:
            cmd_args.append(context["wordlist"])

        target_wordlist_2 = context.get("wordlist_2") or context["wordlist"]
        if context["use_wsl"]:
            cmd_args.append(self._to_wsl_path(target_wordlist_2))
        else:
            cmd_args.append(target_wordlist_2)
        return None, None

    def _mode_combinator_passphrase_args(self, cmd_args, context):
        cmd_args.extend(["-a", "1"])
        if not context["wordlist_2"]:
            return None, "Second wordlist is required for combinator passphrase mode"

        pass_rule_1, pass_rule_2, pass_rule_error = self._resolve_passphrase_rule_paths(
            context["rule_file"],
            context["wordlist"],
            context["hashcat_bin"],
            context["custom_rules_dir"],
        )
        if pass_rule_error:
            return None, pass_rule_error

        context["passphrase_rule_1"] = pass_rule_1
        context["passphrase_rule_2"] = pass_rule_2

        if context["use_wsl"]:
            cmd_args.append(self._to_wsl_path(context["wordlist"]))
            cmd_args.append(self._to_wsl_path(context["wordlist_2"]))
            cmd_args.extend(["-r", self._to_wsl_path(pass_rule_1)])
            cmd_args.extend(["-r", self._to_wsl_path(pass_rule_2)])
        else:
            cmd_args.append(context["wordlist"])
            cmd_args.append(context["wordlist_2"])
            cmd_args.extend(["-r", pass_rule_1])
            cmd_args.extend(["-r", pass_rule_2])
        return None, None

    def _mode_mask_args(self, cmd_args, context):
        cmd_args.extend(["-a", "3"])
        mask = context.get("custom_mask") or "?a?a?a?a?a?a?a?a"
        cmd_args.append(mask)
        return None, None

    def _mode_mask_profile_args(self, cmd_args, context):
        cmd_args.extend(["-a", "3"])
        mask_file = context["mask_file"]
        if not mask_file:
            return None, "Mask profile not selected"
        if not os.path.exists(mask_file):
            return None, f"Mask profile not found: {mask_file}"

        if context["use_wsl"]:
            cmd_args.append(self._to_wsl_path(mask_file))
        else:
            cmd_args.append(mask_file)
        return None, None

    def _mode_hybrid_args(self, cmd_args, context):
        cmd_args.extend(["-a", "6"])
        if context["use_wsl"]:
            cmd_args.append(self._to_wsl_path(context["wordlist"]))
        else:
            cmd_args.append(context["wordlist"])
        mask = context.get("custom_mask") or "?d?d?d?d"
        cmd_args.append(mask)
        return None, None

    def _mode_hybrid_reverse_args(self, cmd_args, context):
        cmd_args.extend(["-a", "7"])
        mask = context.get("custom_mask") or "?d?d?d?d"
        cmd_args.append(mask)
        if context["use_wsl"]:
            cmd_args.append(self._to_wsl_path(context["wordlist"]))
        else:
            cmd_args.append(context["wordlist"])
        return None, None

    def _mode_hybrid_mask_profile_args(self, cmd_args, context):
        cmd_args.extend(["-a", "6"])
        mask_file = context["mask_file"]
        if not mask_file:
            return None, "Mask profile not selected"
        if not os.path.exists(mask_file):
            return None, f"Mask profile not found: {mask_file}"

        if context["use_wsl"]:
            cmd_args.append(self._to_wsl_path(context["wordlist"]))
            cmd_args.append(self._to_wsl_path(mask_file))
        else:
            cmd_args.append(context["wordlist"])
            cmd_args.append(mask_file)
        return None, None

    def _mode_hybrid_reverse_mask_profile_args(self, cmd_args, context):
        cmd_args.extend(["-a", "7"])
        mask_file = context["mask_file"]
        if not mask_file:
            return None, "Mask profile not selected"
        if not os.path.exists(mask_file):
            return None, f"Mask profile not found: {mask_file}"

        if context["use_wsl"]:
            cmd_args.append(self._to_wsl_path(mask_file))
            cmd_args.append(self._to_wsl_path(context["wordlist"]))
        else:
            cmd_args.append(mask_file)
            cmd_args.append(context["wordlist"])
        return None, None

    def _mode_straight_args(self, cmd_args, context):
        cmd_args.extend(["-a", "0"])
        if context["use_wsl"]:
            cmd_args.append(self._to_wsl_path(context["wordlist"]))
        else:
            cmd_args.append(context["wordlist"])
        return None, None

    def _append_mode_specific_args(self, cmd_args, attack_mode, context):
        mode_builders = {
            "rules": self._mode_rules_args,
            "passphrase": self._mode_passphrase_args,
            "digits": self._mode_digits_args,
            "association": self._mode_association_args,
            "association_hint_first": self._mode_association_hint_first_args,
            "association_hint_rule": self._mode_association_hint_rule_args,
            "combinator": self._mode_combinator_args,
            "combinator_passphrase": self._mode_combinator_passphrase_args,
            "mask": self._mode_mask_args,
            "mask_profile": self._mode_mask_profile_args,
            "hybrid": self._mode_hybrid_args,
            "hybrid_reverse": self._mode_hybrid_reverse_args,
            "hybrid_mask_profile": self._mode_hybrid_mask_profile_args,
            "hybrid_reverse_mask_profile": self._mode_hybrid_reverse_mask_profile_args,
        }
        mode_builder = mode_builders.get(attack_mode, self._mode_straight_args)
        return mode_builder(cmd_args, context)

    def _apply_mode_specific_params(
        self,
        params,
        attack_mode,
        context,
        enable_increment,
        increment_min,
        increment_max,
    ):
        if attack_mode == "straight":
            params["wordlist"] = context["wordlist"]
        elif attack_mode == "rules":
            params["wordlist"] = context["wordlist"]
            params["rule"] = context.get("rule_file") or "rules/best64.rule"
        elif attack_mode == "passphrase":
            params["wordlist"] = context["wordlist"]
            params["rule_1"] = context.get("passphrase_rule_1")
            params["rule_2"] = context.get("passphrase_rule_2")
        elif attack_mode == "combinator":
            params["wordlist"] = context["wordlist"]
            params["wordlist_2"] = context.get("wordlist_2") or context["wordlist"]
        elif attack_mode == "combinator_passphrase":
            params["wordlist"] = context["wordlist"]
            params["wordlist_2"] = context["wordlist_2"]
            params["rule_1"] = context.get("passphrase_rule_1")
            params["rule_2"] = context.get("passphrase_rule_2")
        elif self._supports_increment(attack_mode):
            params["mask"] = context["custom_mask"]
            if enable_increment:
                params["increment"] = True
                if increment_min:
                    params["increment_min"] = increment_min
                if increment_max:
                    params["increment_max"] = increment_max
        elif attack_mode == "association":
            params["association_hint"] = context["association_hint"]
            preview = context.get("association_preview") or {}
            if preview:
                params["association_candidates"] = preview.get("candidate_count")
                params["association_capped"] = bool(preview.get("capped"))
        elif attack_mode == "association_hint_first":
            params["association_hints"] = context["association_hints"]
            preview = context.get("association_preview") or {}
            if preview:
                params["association_candidates"] = preview.get("candidate_count")
                params["association_capped"] = bool(preview.get("capped"))
        elif attack_mode == "association_hint_rule":
            params["association_hints"] = context["association_hints"]
            params["rule"] = context.get("rule_file") or "rules/best64.rule"
            preview = context.get("association_preview") or {}
            if preview:
                params["association_candidates"] = preview.get("candidate_count")
                params["association_capped"] = bool(preview.get("capped"))
        elif attack_mode == "mask_profile":
            params["mask_file"] = context["mask_file"]
        elif attack_mode == "hybrid":
            params["wordlist"] = context["wordlist"]
            params["mask"] = context["custom_mask"]
        elif attack_mode == "hybrid_reverse":
            params["mask"] = context["custom_mask"]
            params["wordlist"] = context["wordlist"]
        elif attack_mode == "hybrid_mask_profile":
            params["wordlist"] = context["wordlist"]
            params["mask_file"] = context["mask_file"]
        elif attack_mode == "hybrid_reverse_mask_profile":
            params["mask_file"] = context["mask_file"]
            params["wordlist"] = context["wordlist"]

    def run_attack(
        self,
        hash_filename,
        attack_mode=None,
        workload_profile=None,
        wordlist=None,
        rule_file=None,
        custom_mask=None,
        is_optimized=False,
        is_slow=False,
        device_id=None,
        enable_potfile=False,
        wordlist_2=None,
        enable_increment=False,
        increment_min=None,
        increment_max=None,
        mask_file=None,
        association_hint=None,
        association_hints=None,
        capture_id=None,
        combined_build_id=None,
        mac=None,
    ):
        try:
            conf = self._get_config()
            hashcat_bin = conf.get("hashcat_path", "hashcat")
            custom_rules_dir = conf.get("custom_rules_path", "")

            # LÊ A CONFIGURAÇÃO GLOBAL DE POTFILE
            # Ignora o parâmetro enable_potfile que vem da API (mantido na assinatura por compatibilidade temporária)
            use_potfile = conf.get("hashcat_potfile", False)

            if not attack_mode:
                attack_mode = conf.get("attack_mode", "straight")
            if not workload_profile:
                workload_profile = conf.get("workload_profile", "3")

            if not wordlist and self._requires_wordlist(attack_mode):
                return {"status": "error", "message": "Wordlist not selected"}

            resolved_hash = self._resolve_hash_artifact(
                hash_filename,
                capture_id=capture_id,
                combined_build_id=combined_build_id,
                mac=mac,
            )
            hash_path = resolved_hash.get("path") if resolved_hash else None
            base_name = (
                resolved_hash.get("basename")
                if resolved_hash
                else hash_filename.rsplit(".", 1)[0]
            )
            output_file = (
                get_capture_artifact_path(
                    capture_id,
                    "cracked",
                    handshakes_dir=HANDSHAKES_DIR,
                    ensure_parent=True,
                )
                if capture_id
                else (
                    get_combined_artifact_path(
                        mac,
                        combined_build_id,
                        "cracked",
                        handshakes_dir=HANDSHAKES_DIR,
                        ensure_parent=True,
                    )
                    if combined_build_id
                    else os.path.join(HANDSHAKES_DIR, f"{base_name}.cracked")
                )
            )

            if not hash_path or not os.path.exists(hash_path):
                return {
                    "status": "error",
                    "message": f"Hash file not found: {hash_path}",
                }

            if os.path.exists(output_file):
                try:
                    os.remove(output_file)
                except OSError:
                    pass

            use_wsl = self._should_use_wsl(hashcat_bin)
            cwd = None
            cmd_args = []

            if use_wsl:
                cmd_args.append("wsl")
                cmd_args.append(hashcat_bin)
            else:
                cmd_args.append(hashcat_bin)
                if os.path.isabs(hashcat_bin):
                    cwd = os.path.dirname(hashcat_bin)

            cmd_args.extend(["-m", "22000"])
            cmd_args.extend(["-w", str(workload_profile)])

            effective_optimized = bool(is_optimized)
            if (
                attack_mode in {"association", "association_hint_first"}
                and effective_optimized
            ):
                self.logger.info(
                    "Optimized kernels (-O) disabled for association mode: %s",
                    attack_mode,
                )
                effective_optimized = False

            if effective_optimized:
                cmd_args.append("-O")
            if is_slow and not self._supports_slow_candidates(attack_mode):
                self.logger.info(
                    "Slow candidates disabled for incompatible attack mode: %s",
                    attack_mode,
                )
                is_slow = False

            if is_slow:
                cmd_args.append("-S")

            if device_id and device_id != "all":
                cmd_args.extend(["-d", str(device_id)])

            if use_wsl:
                cmd_args.append(self._to_wsl_path(hash_path))
            else:
                cmd_args.append(hash_path)

            association_candidates_file = None

            # --- CONTAGEM DE ARQUIVOS PARA BARRA DE PROGRESSO GLOBAL ---
            total_steps = 1
            if wordlist:
                target_wordlist_path = wordlist

                # Se for WSL, precisamos resolver o caminho local para contar
                if use_wsl and wordlist.startswith("/mnt/"):
                    # Tentativa básica de reverter wsl path para windows path para contagem
                    # Ex: /mnt/c/wordlists -> C:\wordlists
                    drive = wordlist[5]
                    path_part = wordlist[7:].replace("/", "\\")
                    target_wordlist_path = f"{drive.upper()}:{path_part}"

                if os.path.isdir(target_wordlist_path):
                    try:
                        # Conta arquivos válidos dentro do diretório
                        files = [
                            f
                            for f in os.listdir(target_wordlist_path)
                            if os.path.isfile(os.path.join(target_wordlist_path, f))
                        ]
                        total_steps = len(files)
                        self.logger.info(
                            f"Diretório de wordlist detectado com {total_steps} arquivos."
                        )
                    except Exception as e:
                        self.logger.warning(
                            f"Não foi possível contar arquivos no diretório {target_wordlist_path}: {e}"
                        )

            mode_context = {
                "use_wsl": use_wsl,
                "hash_path": hash_path,
                "wordlist": wordlist,
                "rule_file": rule_file,
                "custom_mask": custom_mask,
                "wordlist_2": wordlist_2,
                "mask_file": mask_file,
                "association_hint": association_hint,
                "association_hints": association_hints,
                "association_preview": None,
                "hashcat_bin": hashcat_bin,
                "custom_rules_dir": custom_rules_dir,
            }
            association_candidates_file, mode_error = self._append_mode_specific_args(
                cmd_args, attack_mode, mode_context
            )
            if mode_error:
                return {"status": "error", "message": mode_error}

            if use_wsl:
                cmd_args.extend(["-o", self._to_wsl_path(output_file)])
            else:
                cmd_args.extend(["-o", output_file])

            # Ensure predictable cracked output: hash:plain:hex_plain
            # Hashcat expects a comma-separated list of fields
            cmd_args.extend(["--outfile-format", "1,2,4", "--outfile-autohex-disable"])

            cmd_args.extend(["--status", "--status-timer", "5", "--force"])

            # Lógica de Potfile baseada na config global
            if not use_potfile:
                cmd_args.append("--potfile-disable")

            # Increment Logic
            if enable_increment and self._supports_increment(attack_mode):
                cmd_args.append("--increment")
                if increment_min:
                    cmd_args.extend(["--increment-min", str(increment_min)])
                if increment_max:
                    cmd_args.extend(["--increment-max", str(increment_max)])

            self.logger.info(f"Iniciando Hashcat: {cmd_args} (CWD: {cwd})")

            # Build params dict based on used arguments
            device_label = None
            device_backend = None
            device_type = None
            if device_id and device_id != "all":
                try:
                    for d in self.get_devices():
                        if str(d.get("id")) == str(device_id):
                            device_label = d.get("name")
                            device_type = d.get("type")
                            device_backend = d.get("backend")
                            break
                except Exception:
                    pass
            elif device_id == "all":
                device_label = "Auto / All"
                device_backend = "Auto"

            if device_label and device_type:
                label_lower = str(device_label).lower()
                type_lower = str(device_type).lower()
                if type_lower not in label_lower:
                    device_label = f"{device_label} {device_type}"

            params = {
                "attack_mode": attack_mode,
                "workload": workload_profile,
                "device": (
                    device_label
                    if device_label
                    else (f"Device #{device_id}" if device_id else None)
                ),
                "potfile": use_potfile,
            }

            if device_backend:
                params["backend"] = device_backend

            if effective_optimized:
                params["optimized"] = True
            if is_slow:
                params["slow"] = True

            self._apply_mode_specific_params(
                params,
                attack_mode,
                mode_context,
                enable_increment,
                increment_min,
                increment_max,
            )

            entry_id = history_service.add_entry(
                hash_filename,
                "hashcat",
                cmd_args,
                params,
                capture_id=capture_id,
                combined_build_id=combined_build_id,
                mac=mac,
            )

            def _cleanup_association_file():
                if association_candidates_file and os.path.exists(
                    association_candidates_file
                ):
                    try:
                        os.remove(association_candidates_file)
                    except Exception:
                        pass

            def on_complete_wrapper(job):
                try:
                    self.process_cracked_file(job)
                    meta = []
                    if job.get("logs"):
                        last_status = None
                        last_recovered = None
                        for line in job["logs"]:
                            clean_line = line.strip()
                            # Filtro melhorado para capturar erros específicos
                            lower_line = clean_line.lower()
                            if (
                                "error" in lower_line
                                or "failed" in lower_line
                                or "exception" in lower_line
                                or "invalid" in lower_line
                            ):
                                meta.append(clean_line)
                            elif "Status..........." in clean_line:
                                last_status = clean_line
                            elif "Recovered........" in clean_line:
                                last_recovered = clean_line
                        if last_status:
                            meta.append(last_status)
                        if last_recovered:
                            meta.append(last_recovered)

                    if job.get("status") == "canceled":
                        history_service.update_entry(
                            hash_filename,
                            entry_id,
                            "CANCELED",
                            "Job canceled by user",
                            meta,
                            capture_id=capture_id,
                            combined_build_id=combined_build_id,
                            mac=mac,
                        )
                        return

                    if job.get("status") == "failed":
                        # Usa a mensagem de erro específica do parser se disponível
                        error_msg = f"Job failed (Code {job.get('return_code', '?')})"
                        if (
                            job.get("progress_data")
                            and job["progress_data"].get("stage") == "ERROR"
                        ):
                            extra = job["progress_data"].get("extra")
                            if extra:
                                error_msg = f"Error: {extra}"

                        history_service.update_entry(
                            hash_filename,
                            entry_id,
                            "FAILED",
                            error_msg,
                            meta,
                            capture_id=capture_id,
                            combined_build_id=combined_build_id,
                            mac=mac,
                        )
                        return

                    if os.path.exists(output_file):
                        history_service.update_entry(
                            hash_filename,
                            entry_id,
                            "CRACKED",
                            "Password found",
                            meta,
                            capture_id=capture_id,
                            combined_build_id=combined_build_id,
                            mac=mac,
                        )
                        from app.services.data_loader import reload_data

                        reload_data()
                        job_manager._fire_and_forget_emit("data_update", "map_data")
                    else:
                        history_service.update_entry(
                            hash_filename,
                            entry_id,
                            "EXHAUSTED",
                            "Password not found",
                            meta,
                            capture_id=capture_id,
                            combined_build_id=combined_build_id,
                            mac=mac,
                        )
                finally:
                    _cleanup_association_file()

            def on_start(job):
                history_service.update_entry(
                    hash_filename,
                    entry_id,
                    "RUNNING",
                    capture_id=capture_id,
                    combined_build_id=combined_build_id,
                    mac=mac,
                )

            # Passa total_steps para o JobManager
            job_id = job_manager.start_job(
                cmd_args,
                job_type="cracking",
                cwd=cwd,
                on_complete=on_complete_wrapper,
                on_start=on_start,
                total_steps=total_steps,
            )

            return {"status": "started", "job_id": job_id}

        except Exception as e:
            assoc_file = locals().get("association_candidates_file")
            if assoc_file and os.path.exists(assoc_file):
                try:
                    os.remove(assoc_file)
                except Exception:
                    pass
            self.logger.error(f"Erro ao iniciar Hashcat: {e}")
            return {"status": "error", "message": str(e)}

    def process_cracked_file(self, job):
        try:
            cracked_file_path = None
            if isinstance(job["command"], list):
                try:
                    idx = job["command"].index("-o")
                    if idx + 1 < len(job["command"]):
                        cracked_file_path = job["command"][idx + 1]
                except ValueError:
                    pass
            else:
                match = re.search(r'-o\s+"?([^"\s]+)"?', job["command"])
                if match:
                    cracked_file_path = match.group(1)

            if not cracked_file_path:
                self.logger.error(
                    f"Não foi possível encontrar o arquivo de saída no comando do job {job['id']}"
                )
                return

            if not os.path.exists(cracked_file_path):
                self.logger.warning(
                    f"Arquivo .cracked não encontrado em {cracked_file_path}, pode não ter sido quebrado."
                )
                return

            base_dir = os.path.dirname(cracked_file_path)
            cracked_base = os.path.basename(cracked_file_path).replace(".cracked", "")
            manifest_path = os.path.join(base_dir, f"{cracked_base}.22000.batch.json")
            if not os.path.exists(manifest_path):
                manifest_path = os.path.join(
                    HANDSHAKES_DIR, f"{cracked_base}.22000.batch.json"
                )

            with open(cracked_file_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]

            if not lines:
                self.logger.warning(f"Arquivo .cracked {cracked_file_path} está vazio.")
                return
            else:
                first_sample = lines[0][:120]
                fmt_hint = "unknown"
                if lines[0].count(":") >= 2 and "*" in lines[0].split(":", 1)[0]:
                    fmt_hint = "hash:plain:hex_plain"
                elif lines[0].count(":") >= 4:
                    fmt_hint = "digest:bssid:sta:essid:password"
                elif lines[0].count(":") >= 1:
                    fmt_hint = "hash:plain"
                self.logger.info(
                    f".cracked format detected: {fmt_hint} | sample: {first_sample}"
                )

            def is_hex(s):
                return re.fullmatch(r"[0-9a-fA-F]+", s or "") is not None

            def decode_essid(hexstr):
                try:
                    return bytes.fromhex(hexstr).decode("utf-8", errors="replace")
                except Exception:
                    return None

            def decode_hex_plain(hexstr):
                try:
                    return bytes.fromhex(hexstr).decode("utf-8", errors="replace")
                except Exception:
                    return None

            # Batch flow: use manifest to map per-network
            if os.path.exists(manifest_path):
                try:
                    with open(manifest_path, "r", encoding="utf-8") as mf:
                        manifest = json.load(mf)
                    items = manifest.get("items", [])
                except Exception as e:
                    self.logger.error(f"Erro ao ler manifest batch: {e}")
                    items = []

                if not items:
                    self.logger.warning(
                        "Manifest batch vazio. Usando fallback para arquivo único."
                    )
                else:
                    mac_map = {}
                    ssid_map = {}
                    ssid_set = set()
                    hash_to_item = {}
                    key_to_item = {}
                    key_no_essid = {}
                    for item in items:
                        mac_clean = (item.get("mac") or "").lower()
                        ssid = item.get("ssid") or ""
                        filename = item.get("filename") or ""
                        if mac_clean:
                            mac_map[mac_clean] = item
                        if ssid:
                            ssid_set.add(ssid)
                            ssid_map.setdefault(ssid, []).append(item)
                        for h in item.get("hashes") or []:
                            if h and h not in hash_to_item:
                                hash_to_item[h] = item
                            try:
                                parts = h.split("*")
                                if len(parts) > 5 and parts[0].upper().startswith(
                                    "WPA"
                                ):
                                    digest = parts[2].lower()
                                    bssid = parts[3].lower()
                                    sta = parts[4].lower()
                                    essid_hex = parts[5]
                                    essid_decoded = decode_essid(essid_hex) or ""

                                    def normalize_essid(val):
                                        if val is None:
                                            return ""
                                        clean = "".join(
                                            ch if ch.isprintable() else ""
                                            for ch in str(val)
                                        )
                                        clean = clean.strip()
                                        clean = re.sub(r"\s+", " ", clean)
                                        return clean

                                    variants = set()
                                    base = normalize_essid(essid_decoded)
                                    if base:
                                        variants.add(base)
                                        variants.add(base.replace("_", " "))
                                        variants.add(base.replace(" ", "_"))
                                        variants.add(base.strip("_"))
                                        variants.add(base.strip())

                                    for v in variants:
                                        key = f"{digest}:{bssid}:{sta}:{v}"
                                        if key and key not in key_to_item:
                                            key_to_item[key] = item

                                    no_essid_key = f"{digest}:{bssid}:{sta}"
                                    if no_essid_key not in key_no_essid:
                                        key_no_essid[no_essid_key] = item
                                    else:
                                        key_no_essid[no_essid_key] = None
                            except Exception:
                                pass

                        for h in item.get("hash_keys") or []:
                            try:
                                parts = h.split(":")
                                if len(parts) == 4:
                                    digest = parts[0].lower()
                                    bssid = parts[1].lower()
                                    sta = parts[2].lower()
                                    essid_hex = parts[3]
                                    essid_decoded = decode_essid(essid_hex) or ""

                                    def normalize_essid(val):
                                        if val is None:
                                            return ""
                                        clean = "".join(
                                            ch if ch.isprintable() else ""
                                            for ch in str(val)
                                        )
                                        clean = clean.strip()
                                        clean = re.sub(r"\s+", " ", clean)
                                        return clean

                                    variants = set()
                                    base = normalize_essid(essid_decoded)
                                    if base:
                                        variants.add(base)
                                        variants.add(base.replace("_", " "))
                                        variants.add(base.replace(" ", "_"))
                                        variants.add(base.strip("_"))
                                        variants.add(base.strip())

                                    for v in variants:
                                        key = f"{digest}:{bssid}:{sta}:{v}"
                                        if key and key not in key_to_item:
                                            key_to_item[key] = item

                                    no_essid_key = f"{digest}:{bssid}:{sta}"
                                    if no_essid_key not in key_no_essid:
                                        key_no_essid[no_essid_key] = item
                                    else:
                                        key_no_essid[no_essid_key] = None
                            except Exception:
                                pass

                    for line in lines:
                        hash_part = None
                        password = None
                        key = None
                        key_no_essid_line = None

                        parts_colon = line.split(":")
                        if len(parts_colon) >= 3 and "*" in parts_colon[0]:
                            hash_part = parts_colon[0].strip()
                            hex_plain = parts_colon[-1].strip()
                            plain = ":".join(parts_colon[1:-1]).strip()
                            if plain:
                                password = plain
                            else:
                                decoded = decode_hex_plain(hex_plain)
                                password = decoded if decoded is not None else hex_plain
                            try:
                                fields = hash_part.split("*")
                                if len(fields) > 5 and fields[0].upper().startswith(
                                    "WPA"
                                ):
                                    digest = fields[2].lower()
                                    bssid = fields[3].lower()
                                    sta = fields[4].lower()
                                    essid_hex = fields[5]
                                    essid_decoded = decode_essid(essid_hex) or ""
                                    if essid_decoded:
                                        key = f"{digest}:{bssid}:{sta}:{essid_decoded}"
                                    key_no_essid_line = f"{digest}:{bssid}:{sta}"
                            except Exception:
                                pass
                        elif len(parts_colon) >= 5:
                            digest = parts_colon[0].lower()
                            bssid = parts_colon[1].lower()
                            sta = parts_colon[2].lower()
                            essid_text = parts_colon[3]
                            if len(parts_colon) >= 6:
                                # Format: digest:bssid:sta:essid:plain:hex_plain
                                password = parts_colon[4]
                                if not password:
                                    decoded = decode_hex_plain(parts_colon[5].strip())
                                    password = (
                                        decoded
                                        if decoded is not None
                                        else parts_colon[5].strip()
                                    )
                                    self.logger.info(
                                        "Batch: plaintext vazio, usando hex_plain decodificado."
                                    )
                            else:
                                password = ":".join(parts_colon[4:])
                            key = f"{digest}:{bssid}:{sta}:{essid_text}"
                            key_no_essid_line = f"{digest}:{bssid}:{sta}"
                        else:
                            try:
                                hash_part, password = line.rsplit(":", 1)
                                hash_part = hash_part.strip()
                            except ValueError:
                                continue

                        target_item = None
                        if key:
                            target_item = key_to_item.get(key)
                        if not target_item and key_no_essid_line:
                            target_item = key_no_essid.get(key_no_essid_line)
                        if not target_item and hash_part:
                            target_item = hash_to_item.get(hash_part)

                        if target_item and password is not None:
                            filename = target_item.get("filename")
                            if filename:
                                base_name = filename.rsplit(".", 1)[0]
                                pcap_cracked_path = os.path.join(
                                    HANDSHAKES_DIR, f"{base_name}.pcap.cracked"
                                )
                                try:
                                    with open(
                                        pcap_cracked_path, "w", encoding="utf-8"
                                    ) as out:
                                        out.write(password)
                                    self.logger.info(
                                        f"Batch: Senha salva em {pcap_cracked_path}"
                                    )
                                except Exception as e:
                                    self.logger.error(
                                        f"Erro ao salvar {pcap_cracked_path}: {e}"
                                    )
                            continue

                        if not hash_part:
                            self.logger.warning(
                                "Batch: hash não mapeado para rede (formato inesperado)"
                            )
                            continue

                        fields = hash_part.split("*")
                        bssid_hex = None
                        essid = None

                        if (
                            len(fields) > 3
                            and is_hex(fields[3])
                            and len(fields[3]) == 12
                        ):
                            bssid_hex = fields[3].lower()

                        if len(fields) > 5 and is_hex(fields[5]):
                            essid_candidate = decode_essid(fields[5])
                            if essid_candidate:
                                essid = essid_candidate

                        if not target_item and not essid and ssid_set:
                            for field in fields:
                                if is_hex(field) and len(field) % 2 == 0:
                                    decoded = decode_essid(field)
                                    if decoded and decoded in ssid_set:
                                        essid = decoded
                                        break

                        if not target_item:
                            if bssid_hex and bssid_hex in mac_map:
                                target_item = mac_map[bssid_hex]
                            elif (
                                essid
                                and essid in ssid_map
                                and len(ssid_map[essid]) == 1
                            ):
                                target_item = ssid_map[essid][0]
                            elif (
                                essid
                                and essid in ssid_map
                                and len(ssid_map[essid]) > 1
                                and bssid_hex
                            ):
                                for item in ssid_map[essid]:
                                    if (item.get("mac") or "").lower() == bssid_hex:
                                        target_item = item
                                        break

                        if not target_item:
                            self.logger.warning(
                                f"Batch: hash não mapeado para rede (line: {hash_part[:40]}...)"
                            )
                            continue

                        filename = target_item.get("filename")
                        if not filename:
                            continue

                        base_name = filename.rsplit(".", 1)[0]
                        pcap_cracked_path = os.path.join(
                            HANDSHAKES_DIR, f"{base_name}.pcap.cracked"
                        )
                        try:
                            with open(pcap_cracked_path, "w", encoding="utf-8") as out:
                                out.write(password)
                            self.logger.info(
                                f"Batch: Senha salva em {pcap_cracked_path}"
                            )
                        except Exception as e:
                            self.logger.error(
                                f"Erro ao salvar {pcap_cracked_path}: {e}"
                            )

                    return

            # Fallback: single file behavior
            first_line = lines[0]
            parts = first_line.split(":")
            if len(parts) < 1:
                self.logger.error(
                    f"Formato inesperado no arquivo .cracked: {first_line}"
                )
                return
            password = parts[-1]
            if len(parts) >= 3 and "*" in parts[0]:
                hex_plain = parts[-1].strip()
                plain = ":".join(parts[1:-1]).strip()
                if plain:
                    password = plain
                else:
                    decoded = decode_hex_plain(hex_plain)
                    password = decoded if decoded is not None else hex_plain

            base_name = f"{cracked_base}.pcap.cracked"
            pcap_cracked_path = os.path.join(base_dir, base_name)

            with open(pcap_cracked_path, "w", encoding="utf-8") as f:
                f.write(password)

            self.logger.info(
                f"Senha extraída '{password}' e salva em {pcap_cracked_path}"
            )

        except Exception as e:
            self.logger.error(
                f"Erro ao processar arquivo .cracked para o job {job['id']}: {e}"
            )
