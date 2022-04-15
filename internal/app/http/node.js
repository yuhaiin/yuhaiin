function latency(id) {
    const test = document.querySelector('#i' + id + ' .test');
    const tcp = document.querySelector('#i' + id + ' .tcp');
    const udp = document.querySelector('#i' + id + ' .udp');

    test.innerText = "Testing...";

    var xmlhttp = new XMLHttpRequest();
    xmlhttp.open("GET", "/latency?hash=" + id, true);
    xmlhttp.send();
    xmlhttp.onreadystatechange = function() {
        let latency = null;
        if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
            latency = JSON.parse(xmlhttp.responseText);
            console.log('get data：', latency);
        }

        if (latency != null && latency.tcp != "") {
            tcp.innerText = latency.tcp;
        } else {
            tcp.innerText = "9999.99ms";
        }

        if (latency != null && latency.udp != "") {
            udp.innerText = latency.udp;
        } else {
            udp.innerText = "9999.99ms";
        }

        test.innerText = "Test";
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