window.onload = function() {
    refresh();
    connect();
}

function connect() {
    var ws = new WebSocket('ws://' + window.location.host + '/statistic');
    window.onbeforeunload = function() {
        ws.close();
    }
    var stt = document.getElementById('statistic');
    ws.onmessage = function(event) {
        let data = JSON.parse(event.data);

        stt.innerText = 'Download(' + data.download + '): ' + data.download_rate +
            '\nUpload(' + data.upload + '): ' + data.upload_rate;
    }

    ws.onclose = function(event) {
        console.log('close websocket, reconnect will in 1 second');
        stt.innerText = 'Loading...';
        setTimeout(connect, 1000);
    }
}

function refresh() {
    var xmlhttp = new XMLHttpRequest();
    let connections = document.getElementById('connections');

    xmlhttp.open("GET", "/connections", true);
    xmlhttp.send();

    xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState != 4) return;
        if (xmlhttp.status == 200) {
            connections.innerHTML = xmlhttp.responseText;
            return
        }

        console.log("get connections failed: " + xmlhttp.status)
    }
}

function close(id) {
    var xmlhttp = new XMLHttpRequest();

    xmlhttp.open("GET", "/conn/close?id=" + id, true);
    xmlhttp.send();

    xmlhttp.onreadystatechange = function() {
        if (xmlhttp.readyState != 4) return;
        if (xmlhttp.status == 200) {
            refresh();
            return
        }

        console.log("close node failed: " + xmlhttp.status)
    }
}