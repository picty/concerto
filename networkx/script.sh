( cat ~/dev/research/concerto/networkx/prefix.py; sed 's/^\(".*"\):\(".*"\)$/(\2,\1),/' *.files/links.csv; cat ~/dev/research/concerto/networkx/suffix.py ) > script.py

python -i script.py
