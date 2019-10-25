// for scaning  Files CV 
// https://www.npmjs.com/package/node-virustotal

// ali
const express = require("express");
const mimeType = require('mime'); // for getting  a mime type  of the scaning file
const path = require("path"); // for getting file name
const app = express();

const port = process.env.PORT || 8000;

// virustotal
const vt = require("node-virustotal");
const fs = require('fs');
const con_virustotal = vt.MakePublicConnection();
const apiKeyForVirustotal = "ee8638fc597e7441387899153afd8ce11d4352d86e101e0b7cd6b69192dbc9b2";

//configiration for virustotal
con_virustotal.setKey(apiKeyForVirustotal);
con_virustotal.setDelay(15000);

//starting server
app.listen(port, () => {
    console.log(`server on port ${port}`)

    //the path for the file what we want to scane CV
    let filePathForScanning = "./likeCV.pdf"

    //* 0 = safe , otherwise unsafe has virus or error for limiting api
    //**********************************************************************************************************************************************************//
    console.log("pls watie for scanning file -- please w8 for getting untile get result/replay")

    // file name  , mimi type ,  file's name "as found in the wild", a mime type "ideally as specific as possible", the actual content of the file
    con_virustotal.submitFileForAnalysis(path.basename(filePathForScanning), mimeType.getType(filePathForScanning), fs.readFileSync(filePathForScanning), function (data_fileAnalysised) {
        //whene the file annylisied from API without any problem

        // console.log("file ananlisised sucssifuly\n", data_fileAnalysised);

        //reporting File after analysing ( scaning file CV)
        con_virustotal.getFileReport(data_fileAnalysised.scan_id, function (theFileReport) {
            //ehen get the report of the file CV
            console.log("#virus diticted=", theFileReport.positives);

        }, function (errorDuringReporeFile) {
            //whene get error in REPORTEING the file
            console.log("report Error DuringReporeFile\n", errorDuringReporeFile);

        });

    }, function (errorDuringAnalysing) {
        // whene get error in Analysing the file
        console.log("errorDuringAnalysing\n ", errorDuringAnalysing);

    });
    //**********************************************************************************************************************************************************//

});
