// Set the contents of the info textbox to the title field of the given element, with line endings replaced suitably.
function setInfoContents(element){
    document.getElementById('infobox').value = element.getAttribute('xlink:title').replace(/\\n/g, '\n');
}

// Make all anchor tags (nodes) in the svg clickable.
for (var el of document.getElementsByTagName("a")) {
    el.setAttribute("onclick", "setInfoContents(this);");
}
