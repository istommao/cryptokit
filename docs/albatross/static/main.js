window.onload = function() {
  var menus = document.getElementsByClassName("dropmenu");
  for (var i = 0;i < menus.length;i++) {
    var menu = menus[i];
    menu.onclick = function(event) {
      var subMenu = this.nextElementSibling;
      if(subMenu.className == "hidden") {
        subMenu.className = "";
      } else {
        subMenu.className = "hidden";
      }
    }
  }
}
