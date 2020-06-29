#!/usr/bin/env bash
# ref: https://github.com/jgm/pandoc/wiki/Using-pandoc-to-produce-reveal.js-slides

input=${1:-"20200622/index.md"}
output_ppt=${2:-"20200622.html"}

usage() {
  cat << HELP
usage: $0 [input] [output]
    input  md源文件路径，如 SummerCamp/index.md
    output html格式PPT输出文件路径，如 20200716.html
example:
    $0 SummerCamp/index.md 20200716.html
HELP
  exit 1
}

if [[ ! -f "$input" ]];then
  usage
fi

pandoc -t revealjs --template=lib/revealjs.template.html -s "${input}" -V theme=white -V transition=fade -V incremental=true -V slideNumber=true -o "${output_ppt}" -V revealjs-url="lib/reveal.js" -V history=true --no-highlight -V hlss=zenburn -V mathjax=true

