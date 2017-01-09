"""
pagify.py: takes a CFG SVG and turns it into an interactive web page.

Tightly coupled with pagify.js. In particular, the infobox id has to match up.
"""
import sys
import os

def pagify(filename:str, out_filename:str=None) -> None:
  """
  Produces an html page from an svg image of a CFG.

  Args:
      filename: the location of the SVG to process
      out_filename: the location to write the html file. By default,
                    the page is written to filename + ".html"
  """
  #
  oname = filename + ".html" if out_filename is None else out_filename
  with open(oname, 'w') as page:
    page.write("""
               <html>
               <body>
               <style>
               .node
               {
                 transition: all 0.05s ease-out;
               }
               .node:hover
               {
                 stroke-width: 1.5;
                 cursor:pointer
               }
               .node:hover
               ellipse
               {
                 fill: #EEE;
               }
               textarea#infobox {
                 position: fixed;
                 display: block;
                 top: 0;
                 right: 0;
               }
               </style>
               """)

    with open(filename, 'r') as svg:
      for line in svg.readlines()[3:]:
        page.write(line)

    page.write("""
               <textarea id="infobox" disabled=true rows=40 cols=100>
               </textarea>
               """)

    page.write("""<script>\n""")
    folder = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(folder, "pagify.js"), 'r') as script:
      for line in script.readlines():
        page.write(" " + line)

    page.write("""
               </script>
               </html>
               </body>
               """)

if __name__ == "__main__":
  if len(sys.argv) < 2:
    print("Please provide an input svg to pagify.")
  else:
    pagify(sys.argv[1])
