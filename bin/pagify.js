
function setInfoContents(element){
    document.getElementById('infobox').value = element.getAttribute('xlink:title').replace(/\\n/g, '\n');
}

for (var el of document.getElementsByTagName("a")) {
    //el.setAttribute("onclick", "document.getElementById('infobox').value = this.getAttribute('xlink:title').replace(/\\n/g, '\n');
    el.setAttribute("onclick", "setInfoContents(this);");
}
