function latency(id, hash) {
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.open("GET", "/latency?hash=" + hash, true);
    xmlhttp.send();
    xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
            console.log('get data：' + JSON.stringify(xmlhttp.responseText));

            document.getElementById(id).innerHTML = xmlhttp.responseText;
        } else {
            document.getElementById(id).innerHTML = '9999.99ms';
        }
    }
}

function del(hash) {
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.open("GET", "/node/delete?hash=" + hash, true);
    xmlhttp.send();
    xmlhttp.onreadystatechange = function() {
        location.reload();
    }
}