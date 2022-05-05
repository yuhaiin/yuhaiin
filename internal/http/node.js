function latency(id) {
    const test = document.querySelector('#i' + id + ' .test');

    test.innerText = "Testing...";

    var tcp = false;
    var udp = false;
    var updateTestText = () => { if (tcp && udp) test.innerText = "Test"; };

    lat(id, "tcp", () => {
        tcp = true;
        updateTestText();
    });
    lat(id, "udp", () => {
        udp = true;
        updateTestText();
    });
}

function lat(id, type, callback) {
    const elem = document.querySelector('#i' + id + ' .' + type);

    var xmlhttp = new XMLHttpRequest();
    xmlhttp.open("GET", "/latency?hash=" + id + "&type=" + type, true);
    xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState != 4) return;
        let latency = null;
        if (xmlhttp.status == 200) {
            latency = xmlhttp.responseText;
            console.log('get ' + type + ' data：', latency);
        }

        elem.innerText = latency != "" ? latency : "9999.99ms";
        callback();
    }
    xmlhttp.send();
}

function del(hash) {
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.open("GET", "/node/delete?hash=" + hash, true);
    xmlhttp.send();
    xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState != 4) return;
        location.reload();
    }
}