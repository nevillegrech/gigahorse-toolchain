import sys

filename = sys.argv[1]

with open(filename + ".html", 'w') as page:
  page.write("<html><body>\n"
             "<style>\n"
             ".node\n{\n  transition: all 0.05s ease-out;\n}\n"
             ".node:hover\n{\n  stroke-width: 1.5;\n  cursor:pointer\n}\n"
             ".node:hover\nellipse\n{\n  fill: #EEE;\n}\n"
             "textarea#infobox {\n"
             "  position: fixed;\n"
             "  display: block;\n"
             "  top: 0;\n"
             "  right: 0;\n}\n"
             "</style>")

  with open(filename, 'r') as svg:
    for line in svg.readlines()[3:]:
      page.write(line)

  page.write("""<textarea id="infobox" disabled=true rows=40 cols=100>\n""")
  page.write("""</textarea>\n""")
  # page.write("""<script src="pagify.js"></script>\n""")
  page.write("""<script>\n""")

  with open("pagify.js", 'r') as script:
    for line in script.readlines():
      page.write(" " + line)

  page.write("""</script>\n""")
  page.write("<html><body>\n")
