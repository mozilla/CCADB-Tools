'use strict';

function focus_caid(){
	$('#ca_id').focus();
	$('#ca_id').effect('highlight');
}

function getCACertInfo(cert_id){
	$.get("/ca_cert/" + parseInt(cert_id).toString(), function(cert_info){
		console.log(cert_info);
		var ts = Date.parse(cert_info.notbefore);
		console.log(ts);
		$('#start_date').val( new Date(ts).toISOString().split('T')[0]);
		$('#start_date').effect('highlight');
	}).fail(function(){
		alert('Error! Could not get certification information.');
	});
}

function getIssuerCAID(){
	var fingerprint_256 	= $('#sha256_fingerprint').val().toLowerCase()
	var fingerprint_1	= $('#sha1_fingerprint').val().toLowerCase()

	console.log("SHA-1 fingerprint:" + fingerprint_1);
	console.log("SHA-256 fingerprint:" + fingerprint_256);

	var fpdata = { "sha256_fingerprint" : fingerprint_256 };
	if(fingerprint_1.length > 0){
		fpdata = { "sha1_fingerprint" : fingerprint_1 };
	}

	$.get("/ca_id", fpdata, function(data){        
		console.log("ca id: " + data);
		$('#ca_id').val(data);
		scrollToID('ca_id', focus_caid);
		getCACertInfo(data);

	//fail
	}).fail(function(){
		alert('Error! Could not find issuing CA ID');
	});
}

function scrollToID(id, f) {
    // Scroll
    $('html,body').animate({
        scrollTop: $("#" + id).offset().top,
	}, {
		complete: f,
		duration: 400
    });
}

function fixLintIssueURL(){
	//$('#lint-button').unbind('click');
	$('#lint-button').on('click', function(){
		var caid = $('#ca_id').val();
		var action_url = "/lint_issues/" + parseInt(caid);
		$('#ca_lint_form').attr('action', action_url);
		if (caid.length == 0){
			alert('Please enter a CA ID or use the fingerprint tool.');
			focus_caid();
			return false;
		}
	});
}

function fixLintSummaryURL(){
	//$('#lint-summary-button').unbind('click');
	$('#lint-summary-button').on('click', function(){
		var caid = $('#ca_id').val();
		var action_url = "/summary/" + parseInt(caid);
		$('#ca_lint_form').attr('action', action_url);
		if (caid.length == 0){
			alert('Please enter a CA ID or use the fingerprint tool.');
			focus_caid();
			return false;
		}
	});
}

window.addEventListener('load', function () {

	/*
	 * $('#ca_id').on('input', function(){
		fixLintIssueURL();
		fixLintSummaryURL();
	});
	*/

	fixLintIssueURL();
	fixLintSummaryURL();

	$('#sha1_fingerprint').on('input', function(){
		$('#sha256_fingerprint').val('');
		//trim whietspace
		$('#sha1_fingerprint').val( $('#sha1_fingerprint').val().replace(/[\s:]+/g,'') );

	});

	$('#sha256_fingerprint').on('input', function(){
		$('#sha1_fingerprint').val('');
		$('#sha256_fingerprint').val( $('#sha256_fingerprint').val().replace(/[\s:]+/g,'') );
	});

	//add todays date as the default end date
	var now = new Date();
	var decade = new Date(2000, 0, 1); 
	$('#end_date').val( now.toISOString().split('T')[0]);
	$('#start_date').val( decade.toISOString().split('T')[0] );


	//JS handle enter press top form
	$('#issuer_ca_id_form .fingerprint-input').keypress(function (e) {
		if (e.which == 13) {
			$('#fingerprint-to-cert-id-btn').click();
			return false;
		}
	});

});
