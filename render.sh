#!/usr/bin/env bash
# ref: https://github.com/jgm/pandoc/wiki/Using-pandoc-to-produce-reveal.js-slides

for input in ./*.md;do
    if [[ "$input" == "./README.md" ]];then
      continue
    fi
    output_ppt="${input}.html"

    pandoc -t revealjs --template=lib/revealjs.template.html -s "${input}" -V theme=white -V transition=fade -V incremental=true -V slideNumber=true -o "${output_ppt}" -V revealjs-url="lib/reveal.js" -V history=true --no-highlight -V hlss=zenburn -V mathjax=true
done
