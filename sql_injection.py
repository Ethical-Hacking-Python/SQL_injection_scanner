import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
from pystyle import Colors, Colorate, Center

with open('resources/ua.txt', 'r') as fichier:
    useragent = fichier.readline().strip() 

error = f"[{Colorate.Horizontal(Colors.red_to_white, '-')}]"
wait = f"[{Colorate.Horizontal(Colors.yellow_to_green, '*')}]"
success = f"[{Colorate.Horizontal(Colors.green_to_cyan, '+')}]"


s = requests.Session()
s.headers["User-Agent"] = f"{useragent}"

def get_all_forms(url):
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    details = {}
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable(response):
    errors = {
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
    }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

def scan_sql_injection(url):
    for c in "\"'":
        new_url = f"{url}{c}"
        print(f"{wait} Trying", new_url)
        res = s.get(new_url)
        if is_vulnerable(res):
            print(f"{success} SQL Injection vulnerability detected, link:", new_url)
            return
    forms = get_all_forms(url)
    print(f"{success} Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)
            if is_vulnerable(res):
                print(f"{success} SQL Injection vulnerability detected, link:", url)
                print(f"{wait} Form:")
                pprint(form_details)
                break

if __name__ == "__main__":
    url = input('website --> ')
    scan_sql_injection(url)
