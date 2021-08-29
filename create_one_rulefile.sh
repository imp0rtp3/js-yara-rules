ls yara |  xargs -I {} bash -c 'cat yara/{} ;echo;' > all_rules.yar
