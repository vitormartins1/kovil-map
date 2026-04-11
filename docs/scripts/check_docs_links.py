#!/usr/bin/env python3
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote


def check_links(docs_dir):
    """
    Verifica links quebrados em arquivos markdown dentro de docs_dir.
    """
    docs_path = Path(docs_dir).resolve()
    broken_links = []
    checked_files = 0

    # Regex para capturar links markdown: [text](link)
    link_pattern = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")

    print(f"🔍 Verificando links em: {docs_path}\n")

    for root, dirs, files in os.walk(docs_path):
        for file in files:
            if not file.endswith(".md"):
                continue

            checked_files += 1
            file_path = Path(root) / file

            try:
                content = file_path.read_text(encoding="utf-8")
            except Exception as e:
                print(f"⚠️  Erro ao ler {file_path}: {e}")
                continue

            for match in link_pattern.finditer(content):
                text, link = match.groups()

                # Ignora links externos, âncoras puras (#) ou emails
                if link.startswith(("http", "https", "mailto:", "ftp:")):
                    continue
                if link.startswith("#"):
                    continue

                # Remove âncoras do link (ex: file.md#section -> file.md)
                clean_link = link.split("#")[0]

                # Se o link era apenas uma ancora interna que virou vazia, ignora (ex: #top)
                if not clean_link:
                    continue

                # Resolve o caminho absoluto do link
                # Se começa com /, considera relativo à raiz do projeto (ajuste conforme necessário)
                # Aqui assumimos links relativos ao arquivo atual
                target_path = (file_path.parent / clean_link).resolve()

                # Decodifica URL (ex: %20 -> espaço)
                target_path_str = unquote(str(target_path))
                target_path = Path(target_path_str)

                if not target_path.exists():
                    broken_links.append(
                        {
                            "file": str(file_path.relative_to(docs_path)),
                            "text": text,
                            "link": link,
                            "resolved": str(target_path),
                        }
                    )

    print(f"✅ Arquivos verificados: {checked_files}")

    if broken_links:
        print(f"❌ Encontrados {len(broken_links)} links quebrados:\n")
        for error in broken_links:
            print(f"📄 Arquivo: docs/{error['file']}")
            print(f"   Link:   [{error['text']}]({error['link']})")
            print("   Erro:   Arquivo não encontrado\n")
        sys.exit(1)
    else:
        print("🎉 Nenhum link quebrado encontrado!")
        sys.exit(0)


if __name__ == "__main__":
    # Assume que o script é rodado da raiz ou da pasta scripts
    root_dir = Path(__file__).resolve().parents[2]
    docs_dir = root_dir / "docs"

    check_links(docs_dir)
