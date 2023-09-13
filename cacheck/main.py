# [START gae_python311_app]
from flask import Flask, render_template, request, jsonify, make_response
from ccadb.db import CCADB
from collections import Counter
from collections.abc import Iterable
import datetime
import itertools
import functools
from lint_dict import LintDict

app = Flask(__name__)
app.config.from_object('config.Config')

def get_lints_json(ca_ids):
    """
        Parses lint issue query options.
    """
    if not isinstance(ca_ids, Iterable) or isinstance(ca_ids, str):
        raise RuntimeError("Error! ca_ids needs to be an iterable - {} passed".format(type(ca_ids)))

    cb_to_bool = lambda x: x.lower() in [ 'on', 'true' ]

    #date ranges
    start   = request.args.get('start', default=None, type=datetime.datetime.fromisoformat)
    end     = request.args.get('end', default=None, type=datetime.datetime.fromisoformat)

    #cert options
    onecrl              = cb_to_bool( request.args.get('onecrl', default="off") )
    expired_certs       = cb_to_bool( request.args.get('expired_certs', default="off") )
    exclude_tech_constrained    = cb_to_bool( request.args.get('exclude_technically_constrained', default="off") )
    exclude_revoked     = cb_to_bool( request.args.get('exclude_revoked', default="off") )

    #lint options
    x509_lint   = cb_to_bool( request.args.get('x509_lint', default="on") )
    cab_lint    = cb_to_bool( request.args.get('cab_lint', default="on") )
    z_lint      = cb_to_bool( request.args.get('z_lint', default="on") )

    daterange   = (start, end)
    linters     = (cab_lint, z_lint, x509_lint)
    cert_options= (onecrl, expired_certs, exclude_revoked, exclude_tech_constrained)

    lint_issue  = request.args.get('lint_issue', default=-1, type=int)

    ccadb = CCADB()
    lint_issues = ccadb.lint_issues_for_ca_ids(map(lambda x: str(x), ca_ids), daterange, cert_options, linters)

    if lint_issue > 0:
        return list(filter(lambda x: x['lint_issue_id'] == lint_issue, lint_issues))

    return lint_issues

@app.route('/lint_issues/<ca_id>', methods=['GET'])
def get_lint_issues(ca_id):
    """
        Dump all lint issues for query options as JSON
    """
    ccadb = CCADB()

    ##max_depth of -1 is infinite
    max_depth = request.args.get('max_depth', default=-1, type=int)
    ca_tree, ca_cn_map = ccadb.build_ca_tree(ca_id, max_depth)
    cca_ids = CCADB._rec_get_keys(ca_tree)
    cca_ids.add(ca_id)

    lint_issues = get_lints_json(cca_ids)

    ##format lint issues by type, then by issue, by issuer
    #bucket into issuers
    ld = LintDict()
    for issue in lint_issues:
        k = issue['issuer_cn'] + issue['issue_text'] + issue['linter']
        ld[k] = ld[k] + [ issue ]

    return render_template( 'lint.html', issuers=ld )


@app.route('/raw_lint_issues/<ca_id>', methods=['GET'])
def get_raw_lint_issues(ca_id):
    """
        Dump all lint issues for query options as JSON
    """
    ccadb = CCADB()

    ##max_depth of -1 is infinite
    max_depth = request.args.get('max_depth', default=-1, type=int)
    ca_tree, ca_cn_map = ccadb.build_ca_tree(ca_id, max_depth)
    cca_ids = CCADB._rec_get_keys(ca_tree)
    cca_ids.add(ca_id)

    return jsonify( get_lints_json(cca_ids) )

def pprint_ca_cert(ccadb, ca_id):
    """
    Print CA cert to meaningful text.
    Strips a certificates public key modulus, signatures, algorithms, raw
    data etc.

    :param ccadb: ccadb instance
    :param ca_id: int(CA ID)
    :return: cert pprint
    :rtype: str
    """
    ca_print = ccadb.pprint_ca_id(ca_id)[0]
    summary_ind_end = ca_print.index("Subject Public Key Info:")
    short_ca_print = ca_print[:summary_ind_end].rstrip()
    lines = short_ca_print.split("\n")
    filt_lines = list(filter(lambda x: 'Certificate:' not in x and
                            'Signature Algorithm:' not in x and
                            'Data:' not in x, lines))
    return '\n'.join(filt_lines).rstrip()

def pprint_cert(ccadb, cert_id):
    """
    Print CA cert to meaningful text.
    Strips a certificates public key modulus, signatures, algorithms, raw
    data etc.

    :param ccadb: ccadb instance
    :param ca_id: int(CA ID)
    :return: cert pprint
    :rtype: str
    """
    cert_info = ccadb.cert_info(cert_id)
    #cert_info['issuer'] = ccadb.cert_info(ccabd. cert_info['id'])
    print(cert_info)
    return cert_info

@app.route('/summary/<ca_id>')
def summary(ca_id):
    """
        Produce a summary of lint issues for a given CA ID.
        This recursively finds lint issues for intermediate 
        and leaf certs.

        :param ca_id: CA ID to build summary
    """
    try:
        ca_id = int(ca_id)
    except ValueError:
        return "Error! Invalid CA ID - {}. Please specify an integer.".format(ca_id), 400

    ##max_depth of -1 is infinite
    max_depth = request.args.get('max_depth', default=-1, type=int)

    #confusion of cert id and ca id 
    #2 different concepts
    ccadb = CCADB()
    ca_tree, ca_cn_map = ccadb.build_ca_tree(ca_id, max_depth)
    cca_ids = CCADB._rec_get_keys(ca_tree)
    cca_ids.add(ca_id)


    cert_id = ccadb.cert_id_from_ca_id(ca_id)

    cert_info = pprint_cert(ccadb, cert_id)
    #except:
    #    return "Error parsing certificate for CA ID {}".format(ca_id), 500

    lints = get_lints_json(cca_ids)
    x509s = list(filter(lambda x: x['linter'] == 'x509lint', lints))
    zs = list(filter(lambda x: x['linter'] == 'zlint', lints))
    cabs = list(filter(lambda x: x['linter'] == 'cablint', lints))

    x509_it = list(map(lambda x: (x['severity'], x['lint_issue_id'], x['issue_text']), x509s))
    x509_issues = Counter(x509_it)

    zs_it = list(map(lambda x: (x['severity'], x['lint_issue_id'], x['issue_text']), zs))
    zs_issues = Counter(zs_it)

    cabs_it = list(map(lambda x: (x['severity'], x['lint_issue_id'], x['issue_text']), cabs))
    cabs_issues = Counter(cabs_it)

    return render_template( 'summary.html', CA_ID=ca_id, x509_issues=x509_issues.items(),
            zs_issues=zs_issues.items(), cabs_issues=cabs_issues.items(), ca_tree=ca_tree, 
            cca_ids=cca_ids, ca_cn_map=ca_cn_map, cert_info=cert_info)

@app.route('/ca_id', methods=['GET'])
def get_ca_id():
    """
        Converts a hex-encoded cert fingerprint to the certs issuing CA ID.
        SHA-256 or SHA-1 may be used.
    """
    sha256_fingerprint  = request.args.get('sha256_fingerprint')
    sha1_fingerprint    = request.args.get('sha1_fingerprint') 

    if not sha1_fingerprint and not sha256_fingerprint:
        return "Error! Please supply a SHA-1 or SHA-256 fingerprint", 400

    digest_type = "sha256" if sha256_fingerprint else "sha1"
    fp = sha256_fingerprint if sha256_fingerprint else sha1_fingerprint

    if len(fp) % 2 != 0:
        return "Error! Odd number of hex characters provided. {}".format(fp), 400

    ccadb = CCADB()
    #return ccadb.issuer_ca_id_from_digest(digest_type, fp)
    return ccadb.ca_id_from_digest(digest_type, fp)

@app.route('/cert/<cert_id>', methods=['GET'])
def get_cert_info(cert_id):
    """
        Dumps JSON certificate information from a cert id
    """
    ccadb = CCADB()
    return jsonify( ccadb.cert_info(int(cert_id)) )

@app.route('/ca_cert/<ca_id>', methods=['GET'])
def get_ca_cert_info(ca_id):
    """
        Dumps JSON certificate information from a cert id
    """
    ccadb = CCADB()
    cert_id = ccadb.cert_id_from_ca_id(int(ca_id))
    return jsonify( ccadb.cert_info(int(cert_id)) )
    
@app.route('/')
def root():
    """
        Renders CAChecker index page.
    """
    resp = make_response( render_template( 'index.html' ) )
    #resp.headers['Access-Control-Allow-Origin'] = '*'
    #resp.headers['Access-Control-Allow-Headers'] = 'x-requested-with'
    return resp

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
# [END gae_python311_app]
