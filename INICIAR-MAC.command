#!/bin/zsh
cd -- "$(dirname -- "$0")" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
  print 'Python3 não encontrado. Consulte LEIA-ME.md.'
  read -r 'resposta?Pressione Enter para fechar...'
  exit 1
fi
python3 backend/app.py
resultado=$?
if [[ $resultado -ne 0 ]]; then
  print 'Consulte LEIA-ME.md e confira se há outro servidor usando a porta8765.'
  read -r 'resposta?Pressione Enter para fechar...'
fi
exit "$resultado"
