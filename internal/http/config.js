function save(id, path) {
    var xmlhttp = new XMLHttpRequest();

    xmlhttp.open("POST", path, true);
    xmlhttp.onload = function() {
        let data = "";
        if (xmlhttp.status != 200) {
            console.log(xmlhttp.status);
            console.log(xmlhttp.responseText);
            data = "Save Failed: " + xmlhttp.responseText;
        } else {
            data = "Save Successful";
            location.reload();
        }
        document.getElementById('error').innerText = data;
    }
    xmlhttp.send(document.getElementById(id).innerText);
}