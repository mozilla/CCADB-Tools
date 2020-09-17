# [START gae_python37_app]
from flask import Flask, render_template, request, jsonify, make_response
from collections import Counter
import datetime
from datetime import datetime, timedelta, date
import bugzilla

app = Flask(__name__)
app.config.from_object('config.Config')

bzapi = bugzilla.Bugzilla(app.config['BZ_URL'])

def query_bugs():
    #no query params to search based on time

    fields = [ 'id', 'weburl', 'summary', 'status', 'resolution', 'creator', 'last_change_time', 'is_open', 'is_confirmed', 'creation_time',
            'assigned_to' ]

    #version=app.config['BUG_VERSION'],
    #status="NEW"
    query = bzapi.build_query(
	    product=app.config['BUG_PRODUCT'],
	    component=app.config['BUG_COMPONENT'],
	    include_fields=fields)

    print("Fetching bugs...")
    bugs = bzapi.query(query)
    print("Got {} bugs form bugzilla".format(len(bugs)))
    return bugs

def extract_bug_info(bugs):
    time_delta  = datetime.today() - timedelta(weeks=1)

    #unresolved_bugs = list(filter(lambda x: x.status != 'RESOLVED' or x.status != 'FIXED', bugs))
    unresolved_bugs = list(filter(lambda x: x.is_open, bugs))
    recent_bugs     = list(filter(lambda x: x.creation_time > time_delta, bugs))
    updated_bugs    = list(filter(lambda x: x.last_change_time > time_delta and x not in recent_bugs, bugs))

    return unresolved_bugs, recent_bugs, updated_bugs



@app.template_filter('parse_user')
def parse_user(email_str):
    return email_str.split('@')[0]

@app.template_filter('parse_timedelta')
def parse_timedelta(ts):
    ts_datetime = datetime.strptime(ts.value, "%Y%m%dT%H:%M:%S")
    now = datetime.now()
    now.replace(microsecond=0)
    timediff = now - ts_datetime
    return "{} days, {} hours, and {} minutes ago".format(timediff.days, timediff.seconds // 3600, (timediff.seconds // 60)% 60)

@app.route('/')
def root():
    """
        Renders CAChecker index page.
    """
    today = datetime.today()
    last_week = today - timedelta(weeks=1)
    un_b, re_b, up_b = extract_bug_info( query_bugs() )
    resp = make_response( render_template( 'index.html', unresolved_bugs=un_b,
        recent_bugs=re_b,
        updated_bugs=up_b,
        date_start=last_week.date(),
        date_end=today.date() ) )
    return resp

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
# [END gae_python37_app]
