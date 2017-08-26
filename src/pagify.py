"""
pagify.py: takes a CFG SVG and turns it into an interactive web page.
"""

from function import FunctionExtractor


def pagify(filename:str,
           function_extractor:FunctionExtractor=None,
           out_filename:str=None) -> None:
  """
  Produces an html page from an svg image of a CFG.

  Args:
      filename: the location of the SVG to process
      function_extractor: a FunctionExtractor object containing functions
                          to annotate the graph with.
      out_filename: the location to write the html file. By default,
                    the page is written to filename + ".html"
  """
  out_name = filename + ".html" if out_filename is None else out_filename
  with open(out_name, 'w') as page:
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
               
               .dropbutton {
                 padding: 10px;
                 border: none;
               }
               .dropbutton:hover, .dropbutton:focus {
                 background-color: #777777;
               }
               .dropdown {
                 margin-right: 5px;
                 float: right;
                 position: relative;
               }
               .dropdown-content {
                 display: none;
                 position: absolute;
                 width: 70px;
                 box-shadow: 0px 5px 10px 0px rgba(0,0,0,0.2);
                 z-index: 1;
               }
               .dropdown-content a {
                 color: black;
                 padding: 8px 10px;
                 text-decoration: none;
                 font-size: 10px;
                 display: block;
               }
               .dropdown-content a:hover {background-color: #f1f1f1}
               .show {display:block;}
               </style>
               """)

    with open(filename, 'r') as svg:
      for line in svg.readlines()[3:]:
        page.write(line)

    page.write("""
               <textarea id="infobox" disabled=true rows=40 cols=80></textarea>
               <div class="dropdown">
                 <button onclick="myFunction()" class="dropbutton">Functions</button>
                 <div id="funclist" class="dropdown-content">
               """)

    if function_extractor is not None:
      for i, f in enumerate(function_extractor.functions):
        if f.is_private:
          page.write('<a href="#">private #{}</a>'.format(i))
        else:
          if f.signature:
            page.write('<a href="#">public {}</a>'.format(f.signature))
          else:
            page.write('<a href="#">fallback</a>')

    page.write("""
                 </div>
               </div>
               <script>
               // Set the contents of the info textbox to the title field of the given element, with line endings replaced suitably.
               function setInfoContents(element){
                   document.getElementById('infobox').value = element.getAttribute('xlink:title').replace(/\\\\n/g, '\\n');
               }

               // Make all anchor tags (nodes) in the svg clickable.
               for (var el of Array.from(document.getElementsByTagName("a"))) {
                   el.setAttribute("onclick", "setInfoContents(this);");
               }
               
               function myFunction() {
                 document.getElementById("funclist").classList.toggle("show");
               }

               window.onclick = function(event) {
                 if (!event.target.matches('.dropbutton')) {
                   var dropdowns = document.getElementsByClassName("dropdown-content");
                   for (var i = 0; i < dropdowns.length; i++) {
                     /*var openDropdown = dropdowns[i];*/
                     if (dropdowns[i].classList.contains('show')) {
                       dropdowns[i].classList.remove('show');
                     }
                   }
                 }
               } 
               </script>
               </html>
               </body>
               """)
