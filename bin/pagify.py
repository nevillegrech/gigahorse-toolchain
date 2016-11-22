import sys

filename = sys.argv[1]

with open(filename + ".html", 'w') as page:
    page.write("<html><body>\n")

    with open(filename, 'r') as svg:
        for line in svg.readlines()[3:]:
            page.write(line)

    page.write("""<textarea id="infobox" disabled=true rows=40 cols=100>\n""")
    page.write("""</textarea>\n""")
    #page.write("""<script src="pagify.js"></script>\n""")
    page.write("""<script>\n""") 

    with open("pagify.js", 'r') as script:
        for line in script.readlines():
            page.write(" " + line)

    page.write("""</script>\n""")
    page.write("<html><body>\n")
