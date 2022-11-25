//webkitURL is deprecated but nevertheless
URL = window.URL || window.webkitURL;

var gumStream;                      //stream from getUserMedia()
var rec;                            //Recorder.js object
var input;                          //MediaStreamAudioSourceNode we'll be recording

// shim for AudioContext when it's not avb.
var AudioContext = window.AudioContext || window.webkitAudioContext;
var audioContext //audio context to help us record


function startRecording() {
    console.log("recordButton clicked");


    var constraints = { audio: true, video:false }



    navigator.mediaDevices.getUserMedia(constraints).then(function(stream) {
        console.log("getUserMedia() success, stream created, initializing Recorder.js ...");

        audioContext = new AudioContext();
        //update the format
        /*  assign to gumStream for later use  */
        gumStream = stream;

        /* use the stream */
        input = audioContext.createMediaStreamSource(stream);

        /*
            Create the Recorder object and configure to record mono sound (1 channel)
            Recording 2 channels  will double the file size
        */
        rec = new Recorder(input,{numChannels:1})

        //start the recording process
        rec.record()

        console.log("Recording started");

    }).catch(function(err) {
        //enable the record button if getUserMedia() fails
        //recordButton.disabled = false;
        //stopButton.disabled = true;
        //pauseButton.disabled = true
    });
}


function stopRecording() {
    console.log("stopButton clicked");
    //tell the recorder to stop the recording
    rec.stop();

    //stop microphone access
    gumStream.getAudioTracks()[0].stop();

    //create the wav blob and pass it on to createDownloadLink
    rec.exportWAV(sendData);
}

function sendData(blob) {

    var url = URL.createObjectURL(blob);
    var filename = new Date().toISOString();
    var xhr=new XMLHttpRequest();
    xhr.onload=function(e) {
              if(this.readyState === 4) {
                  console.log("Server returned: ",e.target.responseText);
              }
          };
          var fd=new FormData();
          fd.append("audio_data",blob, filename);
          xhr.open("POST","/trial_set",true);
          xhr.send(fd);
setTimeout(function () {
      var next=document.getElementById("next");
      next.style.display="block";
},7000);
    //li.appendChild(document.createTextNode (" "))//add a space in between
    //li.appendChild(upload)//add the upload link to li

    //add the li element to the ol
    //recordingsList.appendChild(li);
}