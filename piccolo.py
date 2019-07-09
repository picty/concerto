#!/usr/bin/python

import sqlite3, sys, re, tempfile
from pygraphviz import AGraph
from datetime import datetime
from flask import g, Flask, Response, render_template, abort, session, redirect, url_for
app = Flask(__name__)

DATABASE = sys.argv[1]

trust_flag = "trusted" # TODO: Add code to choose the default trust flag


def make_dicts(cursor, row):
    return dict((cursor.description[idx][0], value)
                for idx, value in enumerate(row))

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = make_dicts
    return db

def query_db(fields, tables, joins, conditions, args=[], order_by=[], group_by=[], offset=None, limit=None):
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
    if limit is None:
        limit_str = ""
    else:
        limit_str = "limit %d" % limit
    if offset is None:
        offset_str = ""
    else:
        offset_str = "offset %d" % offset
    query = ("select %s from %s %s %s %s %s %s %s" %
             (", ".join(fields), ", ".join(tables), join_str, cond_str,
              group_by_str, order_by_str, limit_str, offset_str))
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return rv

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def campaign_str(cid):
    cid_s = "%s" % cid
    if len(cid_s) == 10:
        return "%s-%s-%s/%s" % (cid_s[0:4], cid_s[4:6], cid_s[6:8], cid_s[8:10])
    else:
        return cid_s

def time_str(ts):
    dt = datetime.utcfromtimestamp(ts)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def get_certs(sup_joins, conditions, args, title, group_by_list = []):
    fields = ["certs.hash as hash", "version", "serial",
              "issuer_hash", "dn_i.name as issuer",
              "subject_hash", "dn_s.name as subject",
              "not_before", "not_after",
              "key_type", "rsa_modulus", "rsa_exponent",
              "isCA" ]
    tables = ["certs"]
    joins = ["dns as dn_i on issuer_hash = dn_i.hash",
             "dns as dn_s on subject_hash = dn_s.hash"] + sup_joins
    rv = query_db (fields, tables, joins, conditions, args, group_by = group_by_list)
    if rv:
        if len(rv) == 1:
            cert = rv[0]

            cert["not_before_str"] = time_str (int(cert["not_before"]))
            cert["not_after_str"] = time_str (int(cert["not_after"]))

            if cert['key_type'] == "RSA":
                n = cert['rsa_modulus']
                if n[:2] == "00":
                    n = n[2:]
                cert['key_len'] = len (n) * 4
            else:
                cert['key_len'] = 0

            answers = query_db (["campaign", "ip", "name", "chain_hash", "position", "timestamp"],
                                ["answers"],
                                ["chains on chain_hash = hash"],
                                ["cert_hash = ?"], [cert["hash"]])
            for answer in answers:
                answer["campaign"] = campaign_str(answer["campaign"])
                ts = int(answer["timestamp"])
                answer["timestamp_str"] = time_str (ts)
                answer["valid_at_timestamp"] = str (int(cert["not_before"]) <= ts and ts <= int(cert["not_after"]))

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

            return render_template ("certificate.html", cert=cert, answers=answers, names=names,
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
    return get_certs ([], ["certs.hash = ?"], [certhash], certhash)

@app.route('/certs/by-subject/<subject>')
def cert_by_subject(subject):
    return get_certs ([], ["dn_s.name = ?"], [subject], "subject=%s" % subject)

@app.route('/certs/by-subject-hash/<subject_hash>')
def cert_by_subject_hash(subject_hash):
    return get_certs ([], ["certs.subject_hash = ?"], [subject_hash], "subject_hash=%s" % subject_hash)

@app.route('/certs/by-https-name/<name>')
def cert_by_https_name(name):
    return get_certs (["names on names.cert_hash = certs.hash"],
                      ["names.name = ?"], [name], name, ["certs.hash"])
@app.route('/certs/by-https-name/<type>/<name>')
def cert_by_https_name_bis(type, name):
    return get_certs (["names on names.cert_hash = certs.hash"],
                      ["names.type = ?", "names.name = ?"],
                      [type, name], "%s:%s" % (type, name), ["certs.hash"])

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
              "chain_length", "complete", "ordered", "n_transvalid",
              "built_chains.not_before as not_before", "built_chains.not_after as not_after"]
    tables = ["built_chains"]
    joins = ["built_links on built_links.chain_hash = built_chains.chain_hash " +
               "and built_links.built_chain_number = built_chains.built_chain_number",
             "certs on built_links.cert_hash = certs.hash",
             "dns on certs.subject_hash = dns.hash"] + sup_joins
    conditions = ["built_links.position_in_msg = 0"] + sup_conditions
    rv = query_db (fields, tables, joins, conditions, args,
                   group_by = group_by)
    if rv:
        if len(rv) == 1:
            chain = rv[0]

            for s in ["complete", "ordered"]:
                chain[s + "_str"] = str (int(chain[s]) == 1)
            chain["not_before_str"] = time_str (int(chain["not_before"]))
            chain["not_after_str"] = time_str (int(chain["not_after"]))

            conditions = ["built_chains.chain_hash = ?",
                          "built_chains.built_chain_number = ?"]
            ips = query_db (["campaign", "name", "ip", "answers.timestamp as timestamp",
                             "answers.chain_hash as chain_hash"], ["answers"],
                            ["built_chains on built_chains.chain_hash = answers.chain_hash"],
                            conditions, [chain['chain_hash'], chain['built_chain_number']])
            for ip in ips:
                ip["campaign"] = campaign_str(ip["campaign"])
                ts = int(ip["timestamp"])
                ip["timestamp_str"] = time_str (ts)
                ip["valid_at_timestamp"] = str (int(chain["not_before"]) <= ts and ts <= int(chain["not_after"]))

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
                              [chain['chain_hash'], chain['built_chain_number']], order_by)

            fields = ["certs.hash as cert_hash",
                      "dns.name as subject",
                      "position_in_msg"]
            tables = ["unused_certs"]
            joins = ["certs on certs.hash = unused_certs.cert_hash",
                     "dns on subject_hash = dns.hash"]
            conditions = ["unused_certs.chain_hash = ?",
                          "built_chain_number = ?"]
            unused_certs = query_db (fields, tables, joins, conditions,
                              [chain['chain_hash'], chain['built_chain_number']])

            alt_chains = query_db (["built_chains.built_chain_number", "grade"], ["built_chains"],
                                   ["rated_chains on built_chains.chain_hash = rated_chains.chain_hash and built_chains.built_chain_number = rated_chains.built_chain_number"],
                                   ["built_chains.chain_hash = ?", "built_chains.built_chain_number != ?", "trust_flag= ?"],
                                   [chain['chain_hash'], chain['built_chain_number'], trust_flag])

            grades = query_db (["trust_flag", "grade"], ["rated_chains"], [],
                               ["chain_hash = ?", "built_chain_number = ?"],
                               [chain['chain_hash'], chain['built_chain_number']])


            return render_template ("chain.html", ips = ips, chain=chain,
                                    certs=certs, unused_certs=unused_certs, alt_chains=alt_chains,
                                    grades=grades)
        else:
            fields = ["answers.campaign as campaign", "answers.name as name", "answers.ip as ip",
                      "answers.chain_hash as chain_hash", "answers.timestamp as timestamp", "dns.name as subject",
                      "built_chains.built_chain_number as built_chain_number",
                      "built_chains.not_before as not_before", "built_chains.not_after as not_after",
                      "chain_length", "complete", "ordered", "n_transvalid"]
            tables = ["answers"]
            joins = ["built_chains on built_chains.chain_hash = answers.chain_hash",
                     "built_links on built_links.chain_hash = built_chains.chain_hash " +
                     "and built_links.built_chain_number = built_chains.built_chain_number",
                     "certs on built_links.cert_hash = certs.hash",
                     "dns on certs.subject_hash = dns.hash"] + \
                     filter (lambda j : j != "answers on built_chains.chain_hash = answers.chain_hash", sup_joins)
            conditions = ["built_links.position_in_msg = 0"] + sup_conditions
            rv = query_db (fields, tables, joins, conditions, args,
                           group_by = group_by)
            for result in rv:
                result["campaign"] = campaign_str(result["campaign"])
                ts = int(result["timestamp"])
                result["timestamp_str"] = time_str (ts)
                result["valid_at_timestamp"] = str (int(result["not_before"]) <= ts and ts <= int(result["not_after"]))
            
            return render_template ("chains.html", chains = rv, title = title)
    else:
        abort(404)

@app.route('/chains/<chainhash>')
@app.route('/chains/by-hash/<chainhash>')
def chain_by_hash(chainhash):
    grade = query_db (["built_chain_number"], ["rated_chains"],
                      [], ["trust_flag = ?", "chain_hash = ?"],
                      [trust_flag, chainhash],
                      order_by = ["grade ASC"])
    n = 0
    if grade:
        n = int(grade[0]['built_chain_number'])
    return redirect (url_for ("chain_by_hash_and_number", chainhash=chainhash, pos=n))

@app.route('/chains/by-hash/<chainhash>/<int:pos>')
def chain_by_hash_and_number(chainhash, pos):
    return get_chains ([], ["built_chains.chain_hash = ?", "built_chains.built_chain_number = ?"],
                       [chainhash, pos], "%s - %d" % (chainhash, pos))

@app.route('/chains/by-ip/<ip>')
def chain_by_ip(ip):
    grade = query_db (["built_chain_number"], ["rated_chains"],
                      ["answers on answers.chain_hash = rated_chains.chain_hash"],
                      ["trust_flag = ?", "answers.ip = ?"],
                      [trust_flag, ip],
                      order_by = ["grade ASC"])
    n = 0
    if grade:
        n = int(grade[0]['built_chain_number'])
    return redirect (url_for ("chain_by_ip_and_number", ip=ip, pos=n))

@app.route('/chains/by-ip/<ip>/<int:pos>')
def chain_by_ip_and_number(ip, pos):
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
                      ["%%%s%%" % subject, 0], subject, ["bl.chain_hash"])

# TODO: validite


def tls_version(v):
    if v == "":
        v = 0
    if v == 2:
        return "SSLv2"
    elif v == 768:
        return "SSLv3"
    elif v == 769:
        return "TLS 1.0"
    elif v == 770:
        return "TLS 1.1"
    elif v == 771:
        return "TLS 1.2"
    else:
        return "Unknown TLS version (%4.4x)" % v

def str_of_answer_type(answer):
    try:
        if answer['answer_type'] == 0:
            return "Empty"
        elif answer['answer_type'] == 1:
            return "Junk"
        elif answer['answer_type'] == 10:
            return ("SSLv2 Alert (%s)" % answer['alert_type'])
        elif answer['answer_type'] == 11:
# TODO: Fix this when answers.csv is fixed
#            return ("%s Alert (%s, %s)" % (tls_version (answer['version']), answer['alert_level'], answer['alert_type']))
            return ("TLS Alert (%s, %s)" % (answer['alert_level'], answer['alert_type']))
        elif answer['answer_type'] == 20:
            return ("SSLv2 Handshake (%s)" % answer['ciphersuite'])
        elif answer['answer_type'] == 21:
#            return ("%s Handshake (%s)" % (tls_version (answer['version']), answer['ciphersuite']))
            return ("%s Handshake" % tls_version (answer['version']))
        else:
            return ("Unexpected type (%s)" % answer['answer_type'])
    except:
        return "Unexpected error while processing answer description"

def get_answers(conditions, args, title, offset=None, limit=None):
    fields = ["answers.name as name", "ip", "port", "timestamp",
              "answers.chain_hash as chain_hash", "min(grade) as grade",
              "answer_type", "answers.version as version",
              "ciphersuite", "alert_level", "alert_type"]
    tables = ["answers"]
    joins = ["rated_chains on answers.chain_hash = rated_chains.chain_hash"]
    group_by_list = ["answers.ip", "rated_chains.chain_hash"]
    rv = query_db (fields, tables, joins, conditions, args, group_by = group_by_list, offset=offset, limit=limit)
    if rv:
        for answer in rv:
            answer["timestamp_str"] = time_str (int(answer["timestamp"]))
            answer['type_str'] = str_of_answer_type(answer)

        if len(rv) == 1:
            return render_template ("answer.html", answer=rv[0], title=title)
        else:
            types = dict()
            for answer in rv:
                t = str_of_answer_type(answer)
                if t in types:
                    n = types[t][0]
                else:
                    n = 0
                types[t] = (n+1, t)
                types_list = types.values()
                types_list.sort(reverse=True)
            return render_template ("answers.html", answers=rv, title=title, types = types_list, total=len(rv))
    else:
        abort(404)

@app.route('/answers/<cid>')
def answer_by_campaign(cid):
    return redirect (url_for ("answer_by_campaign_general", cid=cid, start=0, n=100))

@app.route('/answers/<cid>/by-ip/<ip>')
def answer_by_ip(cid, ip):
    return get_answers (["answers.ip = ?", "answers.campaign = ?"], [ip, cid], "Answer(s) from %s in campaign %s" % (ip, cid))

@app.route('/answers/<cid>/<int:start>/<int:n>')
def answer_by_campaign_general(cid, start, n):
    return get_answers (["answers.campaign = ?"], [cid], "Answers in campaign %s" % cid,
                        offset=start, limit=n)


def extract_name (hash, name, short = False):
    if short:
        res = re.sub (r'.*/CN=([^/]+).*', r'\1', name)
        if res == name:
            return hash
        else:
            return res
    else:
        return (re.sub (r'/([A-Z]+)=', r'\n\1=', name)[1:])

def make_chain_graph(chain_hash, built_chain_number=None):
    nodes = []
    sent_certs = []
    built_certs = []
    built_links = []
    names = dict ()
    
    certs = query_db (["position", "cert_hash as hash", "name"], ["chains"],
                      ["certs on cert_hash = certs.hash", "dns on certs.subject_hash = dns.hash"],
                      ["chains.hash = ?"], [chain_hash])
    for cert in certs:
        h = cert['hash']
        nodes.append(h)
        if cert['position'] == 0:
            server_cert = h
        sent_certs.append(h)
        names[h] = extract_name (h, cert['name'])

    built_links = query_db (["distinct cert_hash as hash", "name"], ["built_links"],
                            ["certs on cert_hash = certs.hash", "dns on certs.subject_hash = dns.hash"],
                            ["chain_hash = ?"], [chain_hash])
    for cert in built_links:
        h = cert['hash']
        nodes.append(h)
        names[h] = extract_name (h, cert['name'])


    if built_chain_number != None:
        certs_to_highlight = query_db (["distinct cert_hash as hash", "position_in_chain"], ["built_links"], [],
                            ["chain_hash = ?", "built_chain_number = ?"], [chain_hash, built_chain_number])
        built_chain = dict()
        last = 0
        for cert in certs_to_highlight:
            h = cert['hash']
            pos = int(cert['position_in_chain'])
            built_certs.append (h)
            built_chain[pos] = h
            last = max (last, pos)
        for i in range(last):
            built_links.append ((built_chain[i+1], built_chain[i]))

    nodes = set(nodes)
    edges = []

    for subject in nodes:
        issuers = query_db (["issuer_hash"], ["links"], [],
                            ["subject_hash = ?"], [subject])
        for issuer_obj in issuers:
            issuer = issuer_obj['issuer_hash']
            if issuer in nodes:
                edges.append ((issuer, subject))

    roots_obj = query_db (["cert_hash"], ["roots"], [], ["trust_flag = ?"], [trust_flag])
    roots = set (filter (lambda r : r in nodes, [root_obj['cert_hash'] for root_obj in roots_obj]))

    edges = set(edges)

    g = AGraph(directed=True)

    root_subgraph = g.add_subgraph([], rank="source")

    for c in nodes:
        fillcolor = ""
        style = ""
        shape = ""
        color = ""
        penwidth = ""
        if c in sent_certs:
            fillcolor = "grey"
            style = "filled"
        if c in built_certs:
            color = "red"
            penwidth="2.0"
        if c in roots:
            shape = "rectangle"
        g.add_node ("_%s" % c, label = names[c], fillcolor = fillcolor, style = style,
                    shape = shape, color = color, penwidth = penwidth)
        if c in roots:
            root_subgraph.add_node ("_%s" % c)

    for ((a, b)) in edges:
        if (a, b) in built_links:
            g.add_edge ("_%s" % a, "_%s" % b, color="red", penwidth="2.0")
        else:
            g.add_edge ("_%s" % a, "_%s" % b)

    pngfile = tempfile.TemporaryFile()
    g.draw (path=pngfile, format="png", prog="dot")
    pngfile.seek(0)
    return Response (pngfile.read(), mimetype="image/png")

@app.route('/graph/<chain_hash>')
def make_chain_graph_by_hash_(chain_hash):
    return make_chain_graph (chain_hash)

@app.route('/graph/<chain_hash>/<int:n>')
def make_chain_graph_by_hash_and_number(chain_hash, n):
    return make_chain_graph (chain_hash, built_chain_number = n)

@app.route('/graph-legend')
def make_chain_graph_legend ():
    g = AGraph(directed=True)

    source = g.add_subgraph([], rank="source")
    sink = g.add_subgraph([], rank="sink")

    g.add_node ("root", label = "Trusted\nroot", shape = "rectangle", width="1")
    g.add_node ("sent", label = "Sent\ncertificate", fillcolor = "grey", style = "filled", width="1")
    g.add_edge ("root", "sent", label = "Existing\nlink")

    g.add_node ("issuer", label = "                ", color = "red", penwidth="2.0", width="1")
    g.add_node ("subject", label = "                ", color = "red", penwidth="2.0", width="1")
    g.add_edge ("issuer", "subject", color = "red", label = "Built chain", penwidth="2.0")

    source.add_node ("issuer")
    source.add_node("root")
    sink.add_node ("subject")
    sink.add_node("sent")

    pngfile = tempfile.TemporaryFile()
    g.draw (path=pngfile, format="png", prog="dot")
    pngfile.seek(0)
    return Response (pngfile.read(), mimetype="image/png")



@app.route('/graph/<chain_hash>')
def make_graph_by_hash_(chain_hash):
    return make_graph (chain_hash)


@app.route('/graph/<chain_hash>/<int:n>')
def make_graph_by_hash_and_number(chain_hash, n):
    return make_graph (chain_hash, built_chain_number = n)

@app.route('/graph-legend')
def make_graph_legend():
    return make_graph_legend_image ()


@app.route('/')
def home():
    rv = query_db (["distinct campaign as id", "count(ip) as n"], ["answers"], [], [], group_by=["campaign"])
    return render_template ("home.html", campaigns=rv)


if __name__ == '__main__':
    if len (sys.argv) == 3:
        app.run(debug=True, host=sys.argv[2])
    else:
        app.run(debug=True)
