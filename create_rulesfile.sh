ls yara | awk '{print"include \"yara/"$1"\""}' > all_rules.yar
