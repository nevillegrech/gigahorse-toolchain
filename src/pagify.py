"""
pagify.py: takes a CFG SVG and turns it into an interactive web page.
"""


def pagify(filename:str, out_filename:str=None) -> None:
  """
  Produces an html page from an svg image of a CFG.

  Args:
      filename: the location of the SVG to process
      out_filename: the location to write the html file. By default,
                    the page is written to filename + ".html"
  """
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
               <textarea id="infobox" disabled=true rows=40 cols=100></textarea>
               <script>
               // Set the contents of the info textbox to the title field of the given element, with line endings replaced suitably.
               function setInfoContents(element){
                   document.getElementById('infobox').value = element.getAttribute('xlink:title').replace(/\\\\n/g, '\\n');
               }

               // Make all anchor tags (nodes) in the svg clickable.
               for (var el of Array.from(document.getElementsByTagName("a"))) {
                   el.setAttribute("onclick", "setInfoContents(this);");
               }
               </script>
               </html>
               </body>
               """)
