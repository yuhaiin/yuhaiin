window.onload = function() {
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
        console.log('close websocket')
        stt.innerText = 'Loading...';
    }
}