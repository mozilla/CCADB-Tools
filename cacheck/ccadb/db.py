import psycopg2
import json
import copy
import itertools
from collections.abc import Iterable 
from flask import current_app as app

class CCADB():
    def __init__(self):
        self.conn = self.connect(
            app.config['DB_HOST'], 
            app.config['DB_PORT'], 
            app.config['DB_USER'], 
            app.config['DB_PASS'], 
            app.config['DB_DATABASE']
            )

    def connect(self, host, port, user, passw, database):
        """
        Connects CCADB instance to a Postgres CCADB

        :param host: String: The hostname of the db server
        :param port: Int: port number to connect on
        :param user: String: The username to connect with
        :param passw: String: The password to use
        :param database: String: The database name to use
        :return: None
        :rtype: None
        """
        conn = psycopg2.connect("dbname={} host={} port={} user={} password={}".format(
                database, host, port, user, passw))
        conn.set_session(readonly=True, autocommit=True)
        return conn

    def _query_db(self, query, params):
        """
            Internal helper function, wraps all db queries
            Returns db cursor

            :param query: SQL query string
            :param params: iterable list of params for the query
            :return: A db cursor with the result
            :rtype: psycopg2.cursor
        """
        if not isinstance(params, Iterable):
            raise RuntimeError("SQL query parameters needs to be iterable - {} passed".format(type(params)))

        cursor = self.conn.cursor()
        if app.config['DEBUG']:
            print(query)
            print(params)

        cursor.execute(query, params)
        return cursor

    def issuer_ca_id_from_digest(self, digest, fingerprint):
        """
            Finds certificates based on a digest type and returns the issuing CA ID.

            :param fingerprint: Base64 encoded string that corresponds to the 
            fingerprint of a certificate
            :return: The issuing CA ID of the certificate
            :rtype: int
        """
        cursor = self._query_db("SELECT issuer_ca_id FROM certificate WHERE digest(certificate, %s) = decode(%s, 'hex')", (digest, fingerprint,))
        r = cursor.fetchone()
        if r:
            issuer_ca_id = r[0]
            return str(r[0]), 200
        return "-1", 400

    def ca_id_from_digest(self, digest, fingerprint):
        """
            Finds certificates based on a digest type and returns the CA ID.

            :param fingerprint: Base64 encoded string that corresponds to the 
            fingerprint of a certificate
            :return: The issuing CA ID of the certificate
            :rtype: int
        """
        cursor = self._query_db("""SELECT ca_certificate.ca_id
            FROM certificate 
            LEFT JOIN ca_certificate ON certificate.id=ca_certificate.certificate_id 
            WHERE digest(certificate, %s) = decode(%s, 'hex')""", (digest, fingerprint,))
        r = cursor.fetchone()
        if r:
            issuer_ca_id = r[0]
            return str(r[0]), 200
        return "-1", 400


    def cert_info(self, certificate_id):
        """
            Finds certificates based on a digest type and returns the issuing CA ID.

            :param certificate_id: (int) ID of the certificate to lookup 
            :return: information about the certificate
            :rtype: dict
        """
        if not isinstance(certificate_id, int):
            raise RuntimeError("Error! certificate_id needs to be an int, not {}".format(type(certificate_id)))

        ##WARNING: If any x509* functions fail, rows are not returned
        #x509_extensions(certificate),
        #x509_extkeyusages(certificate),
        #x509_getpathlenconstraint(certificate),
        #x509_altnames(certificate),

        keys = [ 
            'notbefore', 'notafter', 'subjectname', 
            'commonname', 'serialnumber', 'name',
            'authoritykeyid', 'publickey', 'subjectkeyidentifier',
            'issuername'
        ]
        #    'crldistributionpoints', 'authorityinfoaccess', 
        #    'canissuecerts', 'certpolicies',
        #    'keyalgorithm', 'keysize'
        #]
        cert_funcs = map(lambda x: x[0] + x[1] + "(certificate)", zip(itertools.repeat("x509_"), keys))

        cursor = self._query_db("""
        SELECT 
            issuer_ca_id,
            digest(certificate, 'sha256'),
            digest(certificate, 'sha1'),
            {}
        FROM certificate 
        WHERE id=%s
        """.format(", \n\t\t".join(cert_funcs)), 
        (certificate_id, ))
        r = cursor.fetchone()
        if r:
            a = {'issuer_ca_id': r[0], 'id': certificate_id, 
                'sha256_fingerprint': r[1], 'sha1_fingerprint': r[2]
            }
            a.update(dict(zip(keys, r[3:]))) 
            for k, v in a.items():
                if isinstance(v, memoryview):
                    a[k] = v.hex()
            return a
        return "-1"

    def ca_id_from_cert_id(self, cert_id):
        """
            Finds the issuing CA id for a corresponding certificate id

            :param cert_id: int certificate ID
            :return: The issuing CA ID
            :rtype: int
        """
        cursor = self._query_db("""SELECT ca_id from certificate
        LEFT JOIN ca_certificate ON ca_certificate.certificate_id=certificate.id
        WHERE certificate.id=%s""", (cert_id,))
        caid = cursor.fetchone()[0]
        cursor.close()
        return caid

    def cert_id_from_ca_id(self, ca_id):
        """
            Finds the certificate id for the CA 

            :param ca_id: int CA ID
            :return: The certificate id
            :rtype: int
        """
        cursor = self._query_db('SELECT certificate_id from ca_certificate WHERE ca_id=%s', (ca_id,))
        cert_id = cursor.fetchone()[0]
        cursor.close()
        return cert_id

    @staticmethod
    def _rec_get_keys(d):
        """
            recursively get set of all keys in dictionary

            :param d: dict
            :return: set of all keys 
            :rtype: set
        """
        keys = set(map(lambda x: int(x), d.keys()))
        for v in d.values():
            keys = keys.union( CCADB._rec_get_keys(v) )
        return keys

    def build_ca_tree(self, parent_ca_id, depth):
        """
            Build a tree of intermediate CAs

            :param parent_ca_id: int(CA ID) of root
            :param depth: maximum tree depth
            :return: A tree of CA IDs
            :rtype: dict
        """
        skip_ca_ids = set([])
        return self._rec_get_ca_children(parent_ca_id, skip_ca_ids, depth)


    def _rec_get_ca_children(self, ca_id, parent_ca_ids, depth):
        """
            Recursively get CA children and build tree of dicts
            NB: This does not get any cert ids, only CAs

            :param ca_id: int(CA_ID) 
            :param parent_ca_ids: A set of previously seen CA IDs. Ignore a child 
            CA if it is already contained in the tree.
        """
        ca_tree = {}
        if depth == 0:
            return ca_tree, {}
        elif depth == -1:
            pass
        elif depth > 0:
            depth = depth - 1
        else:
            raise RuntimeError("Logic error in recursive CA tree builder. depth is < -1")

        ##get children
        ccas, ca_cn_map = self.get_child_ca_ids(ca_id)
        for cca_id in ccas:
            #skip child ca ids already included
            if cca_id in parent_ca_ids:
                continue

            if not isinstance(cca_id, type(None)):
                parent_ca_ids.add(cca_id)
                cca_tree, cca_cn_map = self._rec_get_ca_children(cca_id, parent_ca_ids, depth)
                ca_tree[cca_id] = cca_tree
                ca_cn_map.update(cca_cn_map)

        return ca_tree, ca_cn_map

    def pprint_ca_id(self, ca_id):
        """
            Finds the issuing CA id for a corresponding certificate id

            :param cert_id: int certificate ID
            :return: The issuing CA ID
            :rtype: int
        """
        cursor = self._query_db("""
        SELECT x509_print(certificate.certificate)
        FROM certificate
        LEFT JOIN ca_certificate
        ON ca_certificate.certificate_id=certificate.id
        WHERE ca_id=%s
        """, (ca_id,))
        return cursor.fetchone()

    def get_child_ca_ids(self, ca_id):
        """
            Finds child CAs from the parent CA ID

            :param ca_id: int CA ID
            :return: A list of child CA IDs
            :rtype: set([int])
        """
        cca_ids = set()
        ca_cn_map = {}
        cursor = self._query_db(
        """
        SELECT ca_id, x509_commonname(certificate.certificate)
        FROM certificate 
        LEFT JOIN ca_certificate 
        ON certificate_id=id 
        WHERE issuer_ca_id=%s 
        AND x509_canissuecerts(certificate.certificate)=True;
        """ , (ca_id,))

        res = cursor.fetchall()
        for cca_id in res:
            if not isinstance(cca_id[0] , type(None)):
                cca_ids.add(cca_id[0])
                ca_cn_map[cca_id[0]] = cca_id[1]

        #remove parent ca_id
        if int(ca_id) in cca_ids:
            cca_ids.remove(int(ca_id))

        cursor.close()
        return cca_ids, ca_cn_map

    def lint_issues_for_ca_ids(self, ca_ids, daterange, cert_options, linters):
        """
            Finds lint issues for a CA id

            :param fingerprint: Base64 encoded string that corresponds to the 
            fingerprint of a certificate
            :return: The issuing CA ID of the certificate
            :rtype: int
        """
        if True not in linters:
            raise RuntimeError("Error! No linters selected!")

        exclude_onecrl, exclude_expired_certs, exclude_revoked, exclude_technically_constrained = cert_options

        lint_names = [ "cablint", "zlint", "x509lint" ]
        query_linter = set(filter(lambda x: x[1], zip(lint_names, linters)))
        query_conf = '{' + ','.join(list(zip(*query_linter))[0]) + '}'
        caids_conf = '{' + ','.join(ca_ids) + '}'

        args = [caids_conf, query_conf]

        if app.config['DEBUG']:
            print("ca ids:", ca_ids, ", start: ", daterange[0], ", end:", daterange[1], ", linters: ", linters)
            print(query_linter)
            print(query_conf)

        sql_query = "SELECT lint_cert_issue.certificate_id, lint_issue.issue_text, lint_issue_id, certificate.issuer_ca_id, x509_notbefore(certificate.certificate), x509_notafter(certificate.certificate), issue_text, linter, severity, "
        sql_query += "x509_issuername(certificate.certificate), x509_subjectname(certificate.certificate), "
        sql_query += "encode(digest(certificate.certificate, 'sha256'), 'hex'), "
        sql_query += "EXISTS(SELECT certificate_id FROM google_revoked WHERE certificate_id=certificate.id), "
        sql_query += "EXISTS(SELECT certificate_id FROM mozilla_onecrl WHERE certificate_id=certificate.id), "
        sql_query += "EXISTS(SELECT certificate_id FROM microsoft_disallowedcert WHERE certificate_id=certificate.id) "
        sql_query += "FROM lint_cert_issue LEFT JOIN lint_issue "
        sql_query += "ON lint_cert_issue.lint_issue_id=lint_issue.id "

        ##left join on certificate to filter expired certificates
        sql_query += "LEFT JOIN certificate "
        sql_query += "ON lint_cert_issue.certificate_id=certificate.id "


        sql_query += "WHERE lint_cert_issue.issuer_ca_id = ANY(%s) "
        #sql_query += "AND linter = ANY('{cablint,x509lint,zlint}')"
        sql_query += "AND linter = ANY(%s) "

        if exclude_expired_certs: 
            sql_query += "AND x509_notafter(certificate.certificate) > NOW() "

        if exclude_technically_constrained:
            #TODO: is_technically_constrained2?
            sql_query += "AND is_technically_constrained(certificate.certificate) = false "

        if daterange[0]:
            sql_query += "AND lint_cert_issue.not_before_date > %s "
            args.append(daterange[0].strftime('%Y-%m-%d'))
        if daterange[1]:
            sql_query += "AND lint_cert_issue.not_before_date < %s "
            args.append(daterange[1].strftime('%Y-%m-%d'))

        if exclude_onecrl:
            sql_query += "AND lint_cert_issue.certificate_id NOT IN ( "
            sql_query += "SELECT certificate_id FROM mozilla_onecrl WHERE certificate_id IS NOT NULL ) "

        cursor = self._query_db(sql_query, args)
        res = cursor.fetchall()

        lint_issues = []
        for r in res:
            print(r)
            fields = [
                'certificate_id', 'issue_text', 'lint_issue_id', 'issuer_ca_id', 'not_before_date', 'not_after_date',
                'issue_text', 'linter', 'severity', 'issuer_cn', 'subject_cn',
                'sha256_fingerprint', 'google_revoked',
                'onecrl_revoked', 'microsoft_revoked'
            ]
            lint_issue = dict(zip(fields, r))
            #if not isinstance(lint_issue['revocation_status'], str):
            #    lint_issue['revocation_status'] = 'Not Revoked'

            if exclude_revoked:
                revoked = False
                for k in [ 'onecrl_revoked', 'microsoft_revoked', 'google_revoked' ]:
                    if lint_issue[k]:
                        revoked = True
                        break

                if not revoked:
                    lint_issues.append(lint_issue)
            else:
                lint_issues.append(lint_issue)

        cursor.close()
        return lint_issues
