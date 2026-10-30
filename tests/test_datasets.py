from pbca.evaluation.datasets import load_cert_windows, load_rba

RBA = """index,Login Timestamp,User ID,Round-Trip Time [ms],IP Address,Country,Region,City,ASN,User Agent String,Browser Name and Version,OS Name and Version,Device Type,Login Successful,Is Attack IP,Is Account Takeover
0,2020-02-03 12:43:30.772,-4324475583306591935,,10.0.65.171,NO,-,-,29695,UA,Firefox 20.0.0.1618,Android 2.3.3.2672,mobile,False,False,False
1,2020-02-03 12:43:43.549,-4324475583306591935,,194.87.207.6,AU,-,-,60117,UA,Chrome 80.0.3987,iOS 13.3,mobile,True,True,True
"""


def test_load_rba(tmp_path):
    p = tmp_path / "rba.csv"
    p.write_text(RBA)
    rows = list(load_rba(p))
    assert len(rows) == 2
    assert rows[0].context.country == "NO" and rows[0].context.asn == "29695" and not rows[0].successful
    assert rows[1].attack_ip and rows[1].account_takeover
    assert len(list(load_rba(p, limit=1))) == 1


def test_load_cert_windows(tmp_path):
    (tmp_path / "file.csv").write_text(
        "id,date,user,pc,filename,content\n"
        "a,01/04/2010 09:01:00,ACM2278,PC-1,x.doc,c\n"
        "b,01/04/2010 09:02:00,ACM2278,PC-1,y.pdf,c\n"
        "c,01/04/2010 09:07:00,ACM2278,PC-1,z.pdf,c\n"
    )
    (tmp_path / "device.csv").write_text(
        "id,date,user,pc,activity\nd,01/04/2010 09:03:00,ACM2278,PC-1,Connect\n"
    )
    (tmp_path / "http.csv").write_text(
        "id,date,user,pc,url,content\ne,01/04/2010 09:04:00,ACM2278,PC-1,http://wikileaks.org/x,c\n"
    )
    answers = tmp_path / "insiders.csv"
    answers.write_text("dataset,scenario,details,user,start,end\n4.2,1,x,ACM2278,01/04/2010 09:00:00,01/04/2010 09:04:59\n")
    windows = load_cert_windows(tmp_path, answers)
    assert len(windows) == 2
    first, second = windows
    assert first.window.records_opened == 2 and first.window.distinct_record_types == 2
    assert first.window.exports == 1 and first.window.unusual_app_requests == 1
    assert first.malicious and not second.malicious
