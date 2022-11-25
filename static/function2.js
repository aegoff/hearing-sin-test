//function delay = ms => new Promise(res => setTimeout(res, ms));

function textGuide()
{document.getElementById("hide").style.display="none";
startRecording();
listen1();
}

function countDown1(sec)
{var timeleft = sec;
var downloadTimer = setInterval(function(){
  if(timeleft > 0){
    //var beep=document.getElementById("beep");
    //beep.play();
    var text=document.getElementById("text");
    text.innerHTML = '<i class="fas fa-microphone"></i>'+ "   "+timeleft + " sec left";
  } else {
    clearInterval(downloadTimer);
    return listen2();
    }
  timeleft -= 1;
}, 1000);}

function countDown2(sec)
{var timeleft = sec;
var downloadTimer = setInterval(function(){
  if(timeleft > 0){
    //var beep=document.getElementById("beep");
    //beep.play();
    var text=document.getElementById("text");
    text.innerHTML = '<i class="fas fa-microphone"></i>'+ "   "+timeleft + " sec left";
  } else {
    clearInterval(downloadTimer);
    return listen3();
    }
  timeleft -= 1;
}, 1000);}


function countDown3(sec)
{var timeleft = sec;
var downloadTimer = setInterval(function(){
  if(timeleft > 0){
    //var beep=document.getElementById("beep");
    //beep.play();
    var text=document.getElementById("text");
    text.innerHTML = '<i class="fas fa-microphone"></i>'+ "   "+timeleft + " sec left";
  } else {
    clearInterval(downloadTimer);
    return listen4();
    }
  timeleft -= 1;
}, 1000);}

function countDown4(sec)
{var timeleft = sec;
var downloadTimer = setInterval(function(){
  if(timeleft > 0){
    //var beep=document.getElementById("beep");
    //beep.play();
    var text=document.getElementById("text");
    text.innerHTML = '<i class="fas fa-microphone"></i>'+ "   "+timeleft + " sec left";
  } else {
    clearInterval(downloadTimer);
    return listen5();
    }
  timeleft -= 1;
}, 1000);}

function countDown5(sec)
{var timeleft = sec;
var downloadTimer = setInterval(function(){
  if(timeleft > 0){
    //var beep=document.getElementById("beep");
    //beep.play();
    var text=document.getElementById("text");
    text.innerHTML = '<i class="fas fa-microphone"></i>'+ "   "+timeleft + " sec left";
  } else {
    clearInterval(downloadTimer);
    return listen6();
    }
  timeleft -= 1;
}, 1000);}

function countDown6(sec)
{var timeleft = sec;
var downloadTimer = setInterval(function(){
  if(timeleft > 0){
    //var beep=document.getElementById("beep");
    //beep.play();
    var text=document.getElementById("text");
    text.innerHTML = '<i class="fas fa-microphone"></i>'+ "   "+timeleft + " sec left";
  } else {
    clearInterval(downloadTimer);
    return done();
    }
  timeleft -= 1;
}, 1000);}

function listen1(){
  var text=document.getElementById("text");
  text.style.color="green";
  text.innerHTML="PLEASE LISTEN";
  var audio1=document.getElementById("audio1");
  audio1.play();
  audio1.onended=function(){
    text.style.color="red";
    text.innerHTML="PLEASE REPEAT THE SENTENCE";
    return countDown1(6);
}}


function listen2(){
  var text=document.getElementById("text");
  text.style.color="green";
  text.innerHTML="PLEASE LISTEN";
  var audio2=document.getElementById("audio2");
  audio2.play();
  audio2.onended=function(){
    text.style.color="red";
    text.innerHTML="PLEASE REPEAT THE SENTENCE";
    return countDown2(6);
}}

function listen3(){
  var text=document.getElementById("text");
  text.style.color="green";
  text.innerHTML="PLEASE LISTEN";
  var audio3=document.getElementById("audio3");
  audio3.play();
  audio3.onended=function(){
    text.style.color="red";
    text.innerHTML="PLEASE REPEAT THE SENTENCE";
    return countDown3(6);
}}

 function listen4(){
  var text=document.getElementById("text");
  text.style.color="green";
  text.innerHTML="PLEASE LISTEN";
  var audio4=document.getElementById("audio4");
  audio4.play();
  audio4.onended=function(){
    text.style.color="red";
    text.innerHTML="PLEASE REPEAT THE SENTENCE";
    return countDown4(6);
}}

 function listen5(){
  var text=document.getElementById("text");
  text.style.color="green";
  text.innerHTML="PLEASE LISTEN";
  var audio5=document.getElementById("audio5");
  audio5.play();
  audio5.onended=function(){
    text.style.color="red";
    text.innerHTML="PLEASE REPEAT THE SENTENCE";
    return countDown5(6);
}}

 function listen6(){
  var text=document.getElementById("text");
  text.style.color="green";
  text.innerHTML="PLEASE LISTEN";
  var audio6=document.getElementById("audio6");
  audio6.play();
  audio6.onended=function(){
    text.style.color="red";
    text.innerHTML="PLEASE REPEAT THE SENTENCE";
    return countDown6(6);
}}


function done(){
  var text=document.getElementById("text");
  text.style.color="black";
 text.innerHTML="COMPLETE!" + "<br />"+ "PLEASE WAIT...";
  return stopRecording();
}