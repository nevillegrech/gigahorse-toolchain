"""pagify.py: takes a CFG SVG and turns it into an interactive web page."""
import sys
import os

def pagify(filename, out_filename=None):
  oname = filename + ".html" if out_filename is None else out_filename
  with open(oname, 'w') as page:
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

    folder = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(folder, "pagify.js"), 'r') as script:
      for line in script.readlines():
        page.write(" " + line)

    page.write("""</script>\n""")
    page.write("<html><body>\n")

if __name__ == "__main__":
  pagify(sys.argv[1])
