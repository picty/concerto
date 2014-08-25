#!/usr/bin/python

import sqlite3, sys
from flask import g, Flask, render_template, abort, session
app = Flask(__name__)

DATABASE = sys.argv[1]

def make_dicts(cursor, row):
    return dict((cursor.description[idx][0], value)
                for idx, value in enumerate(row))

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = make_dicts
    return db

def query_db(fields, tables, joins, conditions, args=[], order_by=[], group_by=[]):
    if len(joins) > 0:
        join_str = "join %s" % (", ".join(joins))
    else:
        join_str = ""
    if len(conditions) > 0:
        cond_str = "where %s" % (" and ".join(conditions))
    else:
        cond_str = ""
    if len(order_by) > 0:
        order_by_str = "order by %s" % (", ".join(order_by))
    else:
        order_by_str = ""
    if len(group_by) > 0:
        group_by_str = "group by %s" % (", ".join(group_by))
    else:
        group_by_str = ""
    query = ("select %s from %s %s %s %s %s" %
             (", ".join(fields), ", ".join(tables), join_str, cond_str, group_by_str, order_by_str))
    print query
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return rv

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def get_certs(sup_joins, conditions, args, title, group_by_list = []):
    fields = ["certs.hash as hash", "version", "serial",
              "issuer_hash", "dn_i.name as issuer",
              "subject_hash", "dn_s.name as subject",
              "notbefore", "notafter",
              "key_type", "rsa_modulus", "rsa_exponent",
              "isCA" ]
    tables = ["certs"]
    joins = ["dns as dn_i on issuer_hash = dn_i.hash",
             "dns as dn_s on subject_hash = dn_s.hash"] + sup_joins
    rv = query_db (fields, tables, joins, conditions, args, group_by = group_by_list)
    if rv:
        if len(rv) == 1:
            cert = rv[0]
            if cert['key_type'] == "RSA":
                n = cert['rsa_modulus']
                if n[:2] == "00":
                    n = n[2:]
                cert['key_len'] = len (n) * 4
            else:
                cert['key_len'] = 0
            names = query_db (["type", "name"], ["names"], [], ["cert_hash = ?"], [cert["hash"]])
            issuers = query_db (["certs.hash as hash", "dns.name as name"], ["dns"],
                                ["certs on certs.subject_hash = dns.hash",
                                 "links on links.issuer_hash = certs.hash"],
                                ["links.subject_hash = ?"], [cert["hash"]])
            issued = query_db (["certs.hash as hash", "dns.name as name"], ["dns"],
                                ["certs on certs.subject_hash = dns.hash",
                                 "links on links.subject_hash = certs.hash"],
                                ["links.issuer_hash = ?"], [cert["hash"]])
            issued_names = query_db (["names.type as type", "names.name as name"],
                                     ["names"],
                                     ["certs on certs.hash = names.cert_hash",
                                      "dns on certs.subject_hash = dns.hash",
                                      "links on links.subject_hash = certs.hash"],
                                     ["links.issuer_hash = ?"], [cert["hash"]])

            transitive_issuers = query_db (["certs.hash as hash", "dns.name as name", "distance"], ["dns"],
                                ["certs on certs.subject_hash = dns.hash",
                                 "transitive_links on transitive_links.issuer_hash = certs.hash"],
                                ["transitive_links.subject_hash = ?"], [cert["hash"]],
                                order_by = ["distance ASC"])
            transitive_issued = query_db (["certs.hash as hash", "dns.name as name", "distance"], ["dns"],
                                ["certs on certs.subject_hash = dns.hash",
                                 "transitive_links on transitive_links.subject_hash = certs.hash"],
                                ["transitive_links.issuer_hash = ?"], [cert["hash"]],
                                order_by = ["distance ASC"])
            transitive_issued_names = query_db (["names.type as type", "names.name as name"],
                                     ["names"],
                                     ["certs on certs.hash = names.cert_hash",
                                      "dns on certs.subject_hash = dns.hash",
                                      "transitive_links on transitive_links.subject_hash = certs.hash"],
                                     ["transitive_links.issuer_hash = ?"], [cert["hash"]])

            return render_template ("certificate.html", cert=cert, names=names,
                                    issuers = issuers, issued = issued, issued_names = issued_names,
                                    transitive_issuers = transitive_issuers, transitive_issued = transitive_issued,
                                    transitive_issued_names = transitive_issued_names)
        else:
            return render_template ("certificates.html", certs = rv, title = title)
    else:
        abort(404)

@app.route('/certs/<certhash>')
@app.route('/certs/by-hash/<certhash>')
def cert_by_hash(certhash):
    return get_certs ([], ["certs.hash LIKE ?"], [certhash + "%"], certhash)

@app.route('/certs/by-subject/<subject>')
def cert_by_subject(subject):
    return get_certs ([], ["dn_s.name LIKE ?"], ["%" + subject + "%"], "subject=%s" % subject)

@app.route('/certs/by-subject-hash/<subject_hash>')
def cert_by_subject_hash(subject_hash):
    return get_certs ([], ["certs.subject_hash LIKE ?"], [subject_hash + "%"], "subject_hash=%s" % subject_hash)

@app.route('/certs/by-https-name/<name>')
def cert_by_https_name(name):
    return get_certs (["names on names.cert_hash = certs.hash"],
                      ["names.name LIKE ?"], ["%" + name + "%"], name, ["certs.hash"])
@app.route('/certs/by-https-name/<type>/<name>')
def cert_by_https_name_bis(type, name):
    return get_certs (["names on names.cert_hash = certs.hash"],
                      ["names.type = ?", "names.name LIKE ?"],
                      [type, "%" + name + "%"], "%s:%s" % (type, name), ["certs.hash"])

@app.route('/certs/by-exact-https-name/<name>')
def cert_by_exact_https_name(name):
    return get_certs (["names on names.cert_hash = certs.hash"],
                      ["names.name = ?"], [name], name, ["certs.hash"])
@app.route('/certs/by-exact-https-name/<type>/<name>')
def cert_by_exact_https_name_bis(type, name):
    return get_certs (["names on names.cert_hash = certs.hash"],
                      ["names.type = ?", "names.name = ?"],
                      [type, name], "%s:%s" % (type, name), ["certs.hash"])



def get_chains(sup_joins, sup_conditions, args, title, group_by = []):
    fields = ["built_chains.chain_hash as chain_hash", "dns.name as subject",
              "built_chains.built_chain_number as built_chain_number",
              "grade", "complete", "trusted", "ordered"]
    tables = ["built_chains"]
    joins = ["built_links on built_links.chain_hash = built_chains.chain_hash " +
               "and built_links.built_chain_number = built_chains.built_chain_number",
             "certs on built_links.cert_hash = certs.hash",
             "dns on certs.subject_hash = dns.hash"] + sup_joins
    conditions = ["built_links.position_in_msg = 0"] + sup_conditions
    rv = query_db (fields, tables, joins, conditions, args,
                   order_by = ["grade DESC"], group_by = group_by)
    if rv:
        if len(rv) == 1:
            conditions = ["built_chains.chain_hash = ?",
                          "built_chains.built_chain_number = ?"]
            ips = query_db (["ip"], ["answers"],
                            ["built_chains on built_chains.chain_hash = answers.chain_hash"],
                            conditions, [rv[0]['chain_hash'], rv[0]['built_chain_number']])
            fields = ["certs.hash as cert_hash",
                      "dns.name as subject",
                      "position_in_msg"]
            tables = ["built_links"]
            joins = ["certs on certs.hash = built_links.cert_hash",
                     "dns on subject_hash = dns.hash"]
            conditions = ["built_links.chain_hash = ?",
                          "built_chain_number = ?"]
            order_by = ["position_in_chain ASC"]
            certs = query_db (fields, tables, joins, conditions,
                              [rv[0]['chain_hash'], rv[0]['built_chain_number']], order_by)

            fields = ["certs.hash as cert_hash",
                      "dns.name as subject",
                      "position_in_msg"]
            tables = ["unused_certs"]
            joins = ["certs on certs.hash = unused_certs.cert_hash",
                     "dns on subject_hash = dns.hash"]
            conditions = ["unused_certs.chain_hash = ?",
                          "built_chain_number = ?"]
            unused_certs = query_db (fields, tables, joins, conditions,
                              [rv[0]['chain_hash'], rv[0]['built_chain_number']])

            alt_chains = query_db (["grade", "built_chain_number"], ["built_chains"], [],
                                   ["chain_hash = ?", "built_chain_number != ?"],
                                   [rv[0]['chain_hash'], rv[0]['built_chain_number']])

            return render_template ("chain.html", ips=", ".join(map (lambda ip : ip["ip"], ips)), chain=rv[0],
                                    certs=certs, unused_certs=unused_certs, alt_chains=alt_chains)
        else:
            fields = ["ip", "answers.chain_hash as chain_hash", "dns.name as subject",
                      "built_chains.built_chain_number as built_chain_number", "grade",
                      "complete", "trusted", "ordered"]
            tables = ["answers"]
            joins = ["built_chains on built_chains.chain_hash = answers.chain_hash",
                     "built_links on built_links.chain_hash = built_chains.chain_hash " +
                     "and built_links.built_chain_number = built_chains.built_chain_number",
                     "certs on built_links.cert_hash = certs.hash",
                     "dns on certs.subject_hash = dns.hash"] + sup_joins
            conditions = ["built_links.position_in_msg = 0"] + sup_conditions
            rv = query_db (fields, tables, joins, conditions, args,
                           order_by = ["grade DESC"], group_by = group_by)
            
            return render_template ("chains.html", chains = rv, title = title)
    else:
        abort(404)

@app.route('/chains/<chainhash>')
@app.route('/chains/by-hash/<chainhash>')
def chain_by_hash(chainhash):
    return get_chains ([], ["built_chains.chain_hash LIKE ?", "built_chains.built_chain_number = ?"],
                       [chainhash + "%", 0], chainhash)

@app.route('/chains/by-hash/<chainhash>/<int:pos>')
def chain_by_hash_and_pos(chainhash, pos):
    return get_chains ([], ["built_chains.chain_hash LIKE ?", "built_chains.built_chain_number = ?"],
                       [chainhash + "%", pos], "%s - %d" % (chainhash, pos))

@app.route('/chains/by-ip/<ip>')
def chain_by_ip(ip):
    return get_chains (["answers on built_chains.chain_hash = answers.chain_hash"],
                       ["answers.ip = ?", "built_chains.built_chain_number = ?"],
                       [ip, 0], ip)

@app.route('/chains/by-ip/<ip>/<int:pos>')
def chain_by_ip_and_pos(ip, pos):
    return get_chains (["answers on built_chains.chain_hash = answers.chain_hash"],
                       ["answers.ip = ?", "built_chains.built_chain_number = ?"],
                       [ip, pos], "%s - %d" % (ip, pos))

@app.route('/chains/by-subject-in-chain/<subject>')
def chain_by_subject_in_chain(subject):
    return get_chains(["built_links as bl on bl.chain_hash = built_chains.chain_hash "
                         "and bl.built_chain_number = built_chains.built_chain_number",
                       "certs as blc on blc.hash = bl.cert_hash",
                       "dns as bldns on bldns.hash = blc.subject_hash"],
                      ["bldns.name LIKE ?", "built_chains.built_chain_number = ?"],
                      ["%" + subject + "%", 0], subject, ["bl.chain_hash"])

# TODO: validite



if __name__ == '__main__':
    app.run(debug=True)
