import * as c from './constants.js';

let inFile, passFile, headerFile;

let DEF = {
  str_max_length : 0,
  ops : 3,
  mem : 134217728,
  passOptSelected : "file",
  headerOptSelected : "file",
};

// check for FileSystem API
let streaming = !!window.showSaveFilePicker;
// used when streaming
let outFile;
let outHandle;
let outStream;
// used when not streaming
let outBuffers;
// writes encrypted/decrypted data to stream or the buffer to be downloaded
let writeData;

// these set up output and kick off worker.js
let startEncryption;
let startDecryption;

let selectFileInputBox = document.getElementById('selectFileInputBox');
let selectFileInputButton = document.getElementById('selectFileInputButton');
let selectFileInputElem = document.getElementById('selectFileInputElem');
let selectFileHeaderButton = document.getElementById('selectFileHeaderButton');
let selectFileHeaderElem = document.getElementById('selectFileHeaderElem');
let textareaHeader = document.getElementById('textareaHeader');
let selectFilePassBox = document.getElementById('selectFilePassBox');
let selectFilePassButton = document.getElementById('selectFilePassButton');
let selectFilePassElem = document.getElementById('selectFilePassElem');
let encryptButton = document.getElementById('encryptButton');
let encryptElem = document.getElementById('encryptElem');
let decryptButton = document.getElementById('decryptButton');
let decryptHeaderButton = document.getElementById('decryptHeaderButton');
let decryptElem = document.getElementById('decryptElem');
let passwordTitle = document.getElementById('passwordTitle');
let passwordBox = document.getElementById('passwordBox');
let progressBar = document.getElementById('progressBar');
let speedSpan = document.getElementById('speed');


let headerOpt = document.getElementById('headerOpt');
let passOpt = document.getElementById('passOpt');
let outputBoxInput = document.getElementById('outputBoxInput');
let outputBoxOutput = document.getElementById('outputBoxOutput');
let outputBoxProcess = document.getElementById('outputBoxProcess');

let startTime;
let progress;
let speed;
let progressInterval;

window.onload = async () => {
  function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
  }
  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    document.addEventListener(eventName, preventDefaults, false);
    selectFileInputBox.addEventListener(eventName, preventDefaults, false);
    selectFilePassBox.addEventListener(eventName, preventDefaults, false);
  });
  /*
  ['dragenter', 'dragover'].forEach(eventName => {
    selectFileInputBox.classList.add('hover');
  });
  ['dragleave', 'drop'].forEach(eventName => {
    selectFileInputBox.classList.remove('hover');
  });
  */
  function handleDrop(e,TargetElement) {
    const dt = e.dataTransfer;
    const files = dt.files;
    TargetElement.files = files;
    TargetElement.dispatchEvent(new Event('change'));
  }
  selectFileInputBox.addEventListener('drop', function(e){
    handleDrop(e,selectFileInputElem);
  }, false);
  selectFilePassBox.addEventListener('drop', function(e){
    handleDrop(e,selectFilePassElem);
  }, false);

  headerOpt.onchange = _=> {
    if(headerOpt.value == 'text'){
      textareaHeader.style = 'display: unset';
      selectFileHeaderButton.style = 'display: none';
    }
    else{
      textareaHeader.style = 'display: none';
      selectFileHeaderButton.style = 'display: unset';
    }
  }
  passOpt.onchange = _=> {
    if(passOpt.value == 'text'){
      passwordBox.style = 'display: unset';
      selectFilePassButton.style = 'display: none';
    }
    else{
      passwordBox.style = 'display: none';
      selectFilePassButton.style = 'display: unset';
    }
  }
  headerOpt.value = DEF.headerOptSelected;
  headerOpt.dispatchEvent(new Event('change'));
  passOpt.value = DEF.passOptSelected;
  passOpt.dispatchEvent(new Event('change'));

  async function fetchPassword(){
    let password, ad = null, ops = DEF.ops, mem = DEF.mem;
    if(passOpt.value == 'text'){
      password = passwordBox.value;
      if(DEF.str_max_length > 0 && password.length > DEF.str_max_length){
        alert("Password length cannot be more than "+DEF.str_max_length+" chars!");
        fail;
      }
    }
    else{
      if(!passFile){
        alert("You didn't select any PassFile!");
        fail;
      }
      let isOnlyNumber = v =>{const regex = /^[0-9]+$/; return regex.test(v);}
      let isUndefined = v => typeof v === 'undefined';
      let PassLines;
      const read = (file) => new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (event) => resolve(event.target.result);
        reader.onerror = reject;
        reader.readAsText(file);
      });
      PassLines = (await read(passFile)).split(/\r?\n/);
      // Password
      password = PassLines[0];
      if(DEF.str_max_length > 0 && password.length > DEF.str_max_length){
        alert("Password length cannot be more than "+DEF.str_max_length+" chars!");
        fail;
      }
      // Ad Strings
      if(!isUndefined(PassLines[1])){
        ad = PassLines[1];
      }
      if(DEF.str_max_length > 0 && ad.length > DEF.str_max_length){
        alert("Ad length cannot be more than "+DEF.str_max_length+" chars!");
        fail;
      }
      // Opslimit
      if(!isUndefined(PassLines[2]) && isOnlyNumber(PassLines[2])){
        ops = PassLines[2];
      }
      // Memlimit
      if(!isUndefined(PassLines[3]) && isOnlyNumber(PassLines[3])){
        mem = PassLines[3];
      }
      //console.log("'"+password+"' "+"'"+ad+"' "+"'"+ops+"' "+"'"+mem+"'"); fail;
    }
    return { password, ad, ops, mem };
  }

  selectFileHeaderButton.onclick = () => {
    selectFileHeaderElem.value = "";
    selectFileHeaderElem.click();
  }
  selectFileHeaderElem.oninput = async () => {
    headerFile = selectFileHeaderElem.files[0];
  }
  selectFilePassButton.onclick = () => {
    selectFilePassElem.value = "";
    selectFilePassElem.click();
  }
  selectFilePassElem.oninput = async () => {
    passFile = selectFilePassElem.files[0];
  }
  selectFileInputButton.onclick = () => {
    selectFileInputElem.value = "";
    selectFileInputElem.click();
  }
  selectFileInputElem.oninput = async () => {
    inFile = selectFileInputElem.files[0];
    /*
    let firstFour = await inFile.slice(0, 4).arrayBuffer();
    firstFour = new Uint8Array(firstFour);
    let hasSignature = compareArrays(firstFour, c.SIGNATURE)
      || compareArrays(firstFour, c.LEGACY_SIGNATURE);
    let decrypting = extensionIsCloaker(inFile.name) || hasSignature;
    if (decrypting) {
      encryptButton.style = 'display: hidden';
      decryptButton.style = 'display: unset';
    } else {
      encryptButton.style = 'display: unset';
      decryptButton.style = 'display: hidden';
    }
    output(`File to ${decrypting ? "decrypt" : "encrypt"}: ${inFile.name}, size: ${getHumanReadableFileSize(inFile.size)}`);
    */
    outputIndi('outputBoxInput',`File to process : <b>${inFile.name}</b>, ${getHumanReadableFileSize(inFile.size)}`);
  }

  encryptButton.onclick = async () => {
    if (!inFile) {
      //output('Please select file.');
      alert('Please select file.');
      return;
    }
    /*
    // check password
    const password = passwordBox.value;
    if (password.length < 12) {
      passwordBox.classList.add('passwordError');
      setTimeout(() => {
        passwordBox.classList.remove('passwordError');
      }, 1000);
      passwordTitle.classList.add('passwordErrorTitle');
      setTimeout(() => {
        passwordTitle.classList.remove('passwordErrorTitle');
      }, 4000);
      return;
    }
    */
    const { password, ad, ops, mem } = await fetchPassword();
    // set up file output
    let name = inFile.name + c.EXTENSION;
    if (streaming) {
      outHandle = await window.showSaveFilePicker({
        suggestedName: name,
        types: [{
          description: 'Cloaker',
          accept: {'application/cloaker': [c.EXTENSION]},
        }],
      });
      outFile = await outHandle.getFile();
      outStream = await outHandle.createWritable();
      name = outFile.name; // use whatever name user picked
    }
    outputIndi('outputBoxOutput',`Encryption Output : <b>${name}</b>`);
    outputIndi('outputBoxProcess',`Encrypting file . . . (it will take time)`);
    startEncryption(inFile, headerFile, password, ad, ops, mem);
  };

  decryptButton.onclick = async () => {
    await decryptFunc();
  };
  decryptHeaderButton.onclick = async () => {
    await decryptFunc(true);
  };
  async function decryptFunc(header=false){
    if (!inFile) {
      //output('Please select file.');
      alert('Please select file.');
      return;
    }
    // const password = passwordBox.value;
    const { password, ad, ops, mem } = await fetchPassword();
    let name = getDecryptFilename(inFile.name);
    if (streaming) {
      outHandle = await window.showSaveFilePicker({
        suggestedName: getDecryptFilename(inFile.name),
      });
      outFile = await outHandle.getFile();
      outStream = await outHandle.createWritable();
      name = outFile.name; // use whatever name user picked
    }
    outputIndi('outputBoxOutput',`Decryption Output : <b>${name}</b>`);
    outputIndi('outputBoxProcess',`Decrypting file . . . (it will take time)`);
    startDecryption(inFile, password, ad, ops, mem, header);
  };
};

let worker = new Worker('./worker.js');

worker.onmessage = (message) => {
  // console.log('main received:', message);
  let bytesPerSecond, download, link, name;
  switch (message.data.response) {
    case c.INITIALIZED_ENCRYPTION:
      launchProgress();
      writeData(message.data.salt);
      writeData(message.data.header);
      worker.postMessage({ command: c.ENCRYPT_CHUNK }); // kick off actual encryption
      break;
    case c.ENCRYPTED_CHUNK:
      if (message.data.header_len != null) {
        writeData(message.data.header_len);
      }
      writeData(message.data.encryptedChunk);
      bytesPerSecond = message.data.bytesWritten / ((Date.now() - startTime) / 1000);
      speed = getHumanReadableFileSize(bytesPerSecond) + ' / sec';
      progress = message.data.progress;
      worker.postMessage({ command: c.ENCRYPT_CHUNK }); // next chunk
      break;
    case c.FINAL_ENCRYPTION:
      writeData(message.data.encryptedChunk);
      if (streaming) {
        name = outFile.name;
        outStream.close();
      } else {
        name = inFile.name + c.EXTENSION;
        download = new File(outBuffers, name);
        link = document.getElementById('downloadLink');
        link.download = name;
        link.href = URL.createObjectURL(download);
        link.innerText = `Download encrypted file "${name}"`
        link.style = 'display: unset';
      }
      outputIndi('outputBoxProcess',`Encryption of <b>${inFile.name}</b> completed.`);
      progressBar.value = message.data.progress;
      clearInterval(progressInterval);
      break;
    case c.ENCRYPTION_FAILED:
      outputIndi('outputBoxProcess','Encryption failed : '+message.data.message);
      clearInterval(progressInterval);
      break;
    case c.INITIALIZED_DECRYPTION:
      launchProgress();
      worker.postMessage({ command: c.DECRYPT_CHUNK }); // kick off decryption
      break;
    case c.DECRYPTED_CHUNK:
      if(message.data.decID > 1){
        writeData(message.data.decryptedChunk);
      }
      bytesPerSecond = message.data.bytesWritten / ((Date.now() - startTime) / 1000);
      speed = getHumanReadableFileSize(bytesPerSecond) + ' / sec';
      progress = message.data.progress;
      worker.postMessage({ command: c.DECRYPT_CHUNK });
      break;
    case c.FINAL_DECRYPTION:
      writeData(message.data.decryptedChunk);
      if (streaming) {
        name = outFile.name;
        outStream.close();
      } else {
        name = getDecryptFilename(inFile.name);
        download = new File(outBuffers, name);
        link = document.getElementById('downloadLink');
        link.download = name;
        link.href = URL.createObjectURL(download);
        link.innerText = `Download decrypted file "${name}"`
        link.style = 'display: unset';
      }
      outputIndi('outputBoxProcess', (message.data.headerDec?"Header ":"")+`Decryption of <b>${inFile.name}</b> completed.`);
      progressBar.value = message.data.headerDec ? 100 : message.data.progress;
      clearInterval(progressInterval);
      break;
    case c.DECRYPTION_FAILED:
      // Change from 'Incorrect password' to a broader and vague description
      // because the failure itself could be from other reasons
      let msg = message.data.message
                ? " : "+ message.data.message
                : ".";
      outputIndi('outputBoxProcess','Decryption failed'+msg);
      clearInterval(progressInterval);
      break;
  }
};

startEncryption = async (inFile, headerFile, password, ad, ops, mem) => {
  startTime = Date.now();
  /*
  let salt = new Uint8Array(c.crypto_pwhash_argon2id_SALTBYTES);
  window.crypto.getRandomValues(salt);
  if (streaming) {
    //outStream.write(c.SIGNATURE);
    outStream.write(salt);
  } else {
    outBuffers = []; // [new Uint8Array(c.SIGNATURE)];
    outBuffers.push(salt);
  }
  */
  outBuffers = [];
  writeData(new TextEncoder().encode(c.SIG_STRING));
  let version_number = new Uint8Array(4);
  new DataView(version_number.buffer).setUint32(0, c.SIG_V_NUMBER, false); // false for big-endian
  writeData(version_number);
  worker.postMessage({ inFile, headerFile, password, ad, ops, mem, command: c.START_ENCRYPTION });
}

startDecryption = async (inFile, password, ad, ops, mem, headerDec) => {
  startTime = Date.now();
  if (!streaming) {
    outBuffers = [];
  }
  worker.postMessage({ inFile, password, ad, ops, mem, headerDec, command: c.START_DECRYPTION });
}

writeData = (data) => {
  if (streaming) {
    outStream.write(data);
  } else {
    outBuffers.push(data);
  }
}

const hideProgress = () => {
  speedSpan.style = 'display: none';
  progressBar.style = 'display: none';
}

const outputIndi = (target, msg) => {
  let targetElem = document.getElementById(target);
  if (window.getComputedStyle(targetElem).display === 'none') {
    targetElem.style = 'display: unset';
  }
  if(target == "outputBoxOutput")
    document.getElementById('outputBoxProcess').style = 'display: none';
  if(target == "outputBoxInput"){
    hideProgress();
    document.getElementById('outputBoxProcess').style = 'display: none';
    document.getElementById('outputBoxOutput').style = 'display: none';
  }
  targetElem.innerHTML = msg;
}

/*
const output = (msg) => {
  if (window.getComputedStyle(outputBox).display === 'none') {
    outputBox.style = 'display: unset';
  }
  let message = document.createElement('span');
  message.textContent = msg;
  outputBox.appendChild(message);
  outputBox.appendChild(document.createElement('br'));
}
*/

const launchProgress = () => {
  speedSpan.style = 'display: unset';
  progressBar.style = 'display: unset';
  progressInterval = setInterval( () => {
    speedSpan.textContent = 'Speed: ' + speed;
    progressBar.value = progress;
  }, 250);
}

const compareArrays = (a1, a2) => {
  if (!a1.length || a1.length != a2.length) {
    return false;
  }
  for (let i = 0; i < a1.length; i++) {
    if (a1[i] != a2[i]) {
      return false;
    }
  }
  return true;
}

const extensionIsCloaker = (filename) => {
  return filename.length > c.EXTENSION.length
    && filename.slice(filename.length - c.EXTENSION.length, filename.length) === c.EXTENSION;
}

const getDecryptFilename = (filename) => {
  // if filename is longer than .cloaker and ends with .cloaker, chop off extension. if not, leave as is and let the user or OS decide.
  let suffixes = [c.EXTENSION, c.EXTENSION + '.txt']; // Chrome on Android adds .cloaker.txt for some reason
  let decryptFilename = filename;
  for (let i in suffixes) {
    let len = suffixes[i].length;
    if (filename.length > len && filename.slice(filename.length - len, filename.length) === suffixes[i]) {
      decryptFilename = filename.slice(0, filename.length - len);
    }
  }
  return decryptFilename;
}

const getHumanReadableFileSize = (size, base=1024) => {
  let index = 0, units = [ "Bytes", "KB", "MB", "GB", "TB" ];
  while (size >= base && index < (units.length-1)) {
    size /= base;
    index++;
  }
  return size.toFixed(2) +" "+ units[index];
}
