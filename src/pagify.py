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
                 position: fixed;
                 top: 5px;
                 right: 0px;
               }
               .dropdown-content {
                 background-color: white;
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
               
               .dropdown-content a:hover { background-color: #f1f1f1; }
               
               .show { display:block; }
               </style>
               """)

    with open(filename, 'r') as svg:
      for line in svg.readlines()[3:]:
        page.write(line)

    page.write("""<textarea id="infobox" disabled=true rows=40 cols=80></textarea>""")

    # Create a dropdown list of functions if there are any.
    if function_extractor is not None:
      page.write("""<div class="dropdown">
                 <button onclick="showDropdown()" class="dropbutton">Functions</button>
                 <div id="func-list" class="dropdown-content">""")

      for i, f in enumerate(function_extractor.functions):
        if f.is_private:
          page.write('<a id=f_{0} href="javascript:highlightFunction({0})">private #{0}</a>'.format(i))
        else:
          if f.signature:
            page.write('<a id=f_{0} href="javascript:highlightFunction({0})">public {1}</a>'.format(i, f.signature))
          else:
            page.write('<a id=f_{0} href="javascript:highlightFunction({0})">fallback</a>'.format(i))
      page.write("</div></div>")

    page.write("""<script>""")

    if function_extractor is not None:
      func_map = {i: [b.ident() for b in f.body]
                  for i, f in enumerate(function_extractor.functions)}
      page.write("var func_map = {};".format(func_map))
      page.write("var highlight = new Array({}).fill(0);".format(len(func_map)))

    page.write("""
               
               // Set info textbox contents to the title of the given element, with line endings replaced suitably.
               function setInfoContents(element){
                   document.getElementById('infobox').value = element.getAttribute('xlink:title').replace(/\\\\n/g, '\\n');
               }

               // Make all node anchor tags in the svg clickable.
               for (var el of Array.from(document.querySelectorAll(".node a"))) {
                   el.setAttribute("onclick", "setInfoContents(this);");
               }
               
               const svg = document.querySelector('svg')
               const NS = "http://www.w3.org/2000/svg";
               const defs = document.createElementNS( NS, "defs" );

               // IIFE add filter to svg to allow shadows to be added to nodes within it
               (function(){
                 defs.innerHTML = makeShadowFilter()
                 svg.insertBefore(defs,svg.children[0])
               })()
               
               function colorToID(color){
                 return color.replace(/[^a-zA-Z0-9]/g,'_')
               }

               function makeShadowFilter({color = 'black',x = 0,y = 0, blur = 3} = {}){
                 return `
                 <filter id="filter_${colorToID(color)}" x="-40%" y="-40%" width="250%" height="250%">
                   <feGaussianBlur in="SourceAlpha" stdDeviation="${blur}"/>
                   <feOffset dx="${x}" dy="${y}" result="offsetblur"/>
                   <feFlood flood-color="${color}"/>
                   <feComposite in2="offsetblur" operator="in"/>
                   <feMerge>
                     <feMergeNode/>
                     <feMergeNode in="SourceGraphic"/>
                   </feMerge>
                 </filter>
                 `
               }

               // Shadow toggle functions, with filter caching
               function addShadow(el, {color = 'black',x = 0,y = 0, blur = 3}){
                 const id = colorToID(color)
                 if(!defs.querySelector(`#filter_${id}`)){
                   const filter = document.createElementNS(NS,'filter')
                   defs.appendChild(filter)
                   filter.outerHTML = makeShadowFilter({color,x,y,blur})
                 }
                 el.style.filter = `url(#filter_${id})`
               }
               function removeShadow(el){
                 el.style.filter = ''
               }  
               
               function hash(n) {
                 var str = n + "rainbows" + n + "please" + n
                 var hash = 0;
                 for (var i = 0; i < str.length; i++) {
                   hash = (((hash << 5) - hash) + str.charCodeAt(i)) | 0;
                 }
                 return hash > 0 ? hash : -hash;
               }; 
               
               function getColor(n, sat="80%", light="50%") {
                 const hue = hash(n) % 360;
                 return `hsl(${hue}, ${sat}, ${light})`;
               }
                
               // Add shadows to function body nodes, and highlight functions in the dropdown list
               function highlightFunction(i) {
                 for (var n of document.querySelectorAll(".node ellipse")) {
                   removeShadow(n);
                 }
                 
                 highlight[i] = !highlight[i];
                 const entry = document.querySelector(`.dropdown-content a[id='f_${i}']`)
                 if (entry.style.backgroundColor) {
                   entry.style.backgroundColor = null;
                 } else {
                   entry.style.backgroundColor = getColor(i, "60%", "90%");
                 }
                 
                 for (var j = 0; j < highlight.length; j++) {
                   if (highlight[j]) {
                     const col = getColor(j);
                     for (var id of func_map[j]) {
                       var n = document.querySelector(`.node[id='${id}'] ellipse`);
                       addShadow(n, {color:`${col}`});
                     }
                   }
                 }
               }
               
               // Show the dropdown elements when it's clicked.
               function showDropdown() {
                 document.getElementById("func-list").classList.toggle("show");
               }
               window.onclick = function(event) {
                 if (!event.target.matches('.dropbutton')) {
                   var items = document.getElementsByClassName("dropdown-content");
                   for (var item of items) {
                     item.classList.remove('show');
                   }
                 }
               } 
              </script>
              </html>
              </body>
              """)
