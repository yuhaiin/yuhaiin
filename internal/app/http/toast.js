function show_toast(text) {
    var x = document.getElementById("snackbar");
    x.innerText = text;
    x.className = "show";
    setTimeout(function() { x.className = x.className.replace("show", ""); }, 3000);
}