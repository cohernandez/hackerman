#!/usr/bin/env python3
"""Command-Line interface para realizar Security Test"""

import whois
import time
import typer
import nmap3
import requests
import json
import warnings
import subprocess
from lxml import html
from Wappalyzer import Wappalyzer, WebPage

app = typer.Typer()

# Workaround para https://github.com/chorsley/python-Wappalyzer/issues/40
warnings.simplefilter("ignore") 


def getPage(url:str, proxy:str = None):
    """Ejecuta una peticion GET y retorna el objeto respuesta"""
    proxies=None
    if proxy:
        proxies={"http": f"http://{proxy}"}
    response = requests.get(url,proxies=proxies)
    return response

def postPage(url:str, proxy:str = None, data:dict=None):
    """Ejecuta una peticion POST y retorna la respuesta del objeto"""
    proxies=None
    if proxy:
        proxies={"http": f"http://{proxy}"}
    response = requests.post(url,proxies=proxies, data=data, allow_redirects=False)
    return response

# Suggestion du Chef:
@app.command()
def domain(name:str):
    """Imprime los datos de query whois del dominio objetivo"""
    resultados = whois.whois(name)
    print(f"{name} [*]: Esta registrado por {resultados.name} - {resultados.org} - {resultados.email} ")
    

@app.command()
def login(
    url:str,
    username:str,
    password:str,
    uservariable:str ="username",
    proxy:str = None,
    ):
    """POST un Usuario y Password"""
    data = {uservariable: username, "password": password}
    response = postPage(url, proxy=proxy ,data=data)
    if response.status_code == 302:
        if url in response.headers["Location"]:
            return False
        print(f"Redirijido a: {response.headers['Location']}")
    print(f"Login realizado con Usuario: {username} y Password: {password}")
    if response.content:
        print(response.content)
    if response.cookies:
        print(f"Cookie Recibida: {response.cookies}")
    return True


@app.command()
def csrf(
    url:str,
    csrftoken:str,
    email:str,
    firstname:str,
    lastname:str,
    company:str,
    country:str,
    locale:str,
    password:str,
    uservariable:str ="email",
    proxy:str = None,
    ):
    """Testing de csrf"""
    data = {uservariable: email, "csrftoken": csrftoken, "email":email, "firstname":firstname, "lastname":lastname,"company":company,"country":country, "locale":locale}
    response = postPage(url, proxy=proxy ,data=data)
    if response.status_code == 302:
        if url in response.headers["Location"]:
            return False
        print(f"Redirijido a: {response.headers['Location']}")
    print(f"Login realizado con Usuario: {email} y Password: {password}")
    if response.content:
        print(response.content)
    if response.cookies:
        print(f"Cookie Recibida: {response.cookies}")
    return True



@app.command()
def brute(url:str, username: str, wordlist:str, proxy:str=None):
    """Fuerza bruta para login de password usando un wordlist!"""
    with open(wordlist, encoding="utf-8") as handle:
        passwords = handle.read().splitlines()
    for password in passwords:
        if login(url, username, password, proxy=proxy):
            break
    


@app.command()
def portScan(target:str, top:int = 1000):
    """Escanea los Top 1000 puertos del objetivo e imprime su puerto y servicio"""
    nmap = nmap3.Nmap()
    resultados = nmap.scan_top_ports(target, default =top)
    ip, *_unused = resultados.keys()
    for port in resultados[ip]["ports"]:
        if "open" in port["state"]:
            print(f"{port['portid']} {port['service']['name']} ")

@app.command()
def scan_all_ports(target:str):
    """Escanea todos los puertos TCP abiertos del objetivo e imprime su puerto y servicio"""
    #nmap --script smb-enum-shares.nse -p445
    nmap = nmap3.NmapScanTechniques()
    resultados = nmap.nmap_tcp_scan(target)
    ip, *_unused = resultados.keys()
    for port in resultados[ip]["ports"]:
        if "open" in port["state"]:
            print(f"{port['portid']} {port['service']['name']} ")

@app.command()
def forms(url:str, proxy:str =None):
    """Busca un formulario en una pagina e imprime los detalles del formulario"""
    response = getPage(url,proxy)
    tree = html.fromstring(response.content)
    for form in tree.xpath("//form"):
        print(f"[*] Se encontro un formulario: {form.method} para un: {form.action}")
        for field in form.fields:
            print(f"Contiene el campo input: {field}")

@app.command()
def analyze(url:str, proxy:str =None):
    """Analiza el stack de tecnologia de la aplicacion web e imprime los detalles"""
    response = getPage(url,proxy)
    webpage = WebPage.new_from_response(response)
    wappalyzer = Wappalyzer.latest()
    results = wappalyzer.analyze_with_versions_and_categories(webpage)
    print(json.dumps(results, indent=2))

@app.command()
def discover(url: str, wordlist: str = "/dev/null"):
    """Brute-force de archivos y directorios."""
    subprocess.run(["gobuster", "-u", url, "-w", wordlist], check=True)

@app.command()
def impersonalizacion(url:str):
    """Cambiar el comportamiento de las solicitudes que realiza a un sitio web"""
    useragentstring = {'User-Agent':'Bad_Actor_UserAgentString_v1'}
    pageresponse = requests.get(url, headers=useragentstring)
    print(pageresponse.content)

@app.command()
def dirbust(url:str):
    """Busca recursos ocultos y archivos confidenciales, Ej: ./hackerman.py dirbust https://test.fr/"""
    dictionaryfile = open("dictionary.txt","r")
    for line in dictionaryfile:
        addresstotest = url + "/" + line.strip()
        print('Testing: '+addresstotest)
        pageresponse = requests.get(addresstotest)
        
        if pageresponse:
            print(f"Recurso encontrado:"+addresstotest)


@app.command()
def sniper(url: str):
    """RedTeamTool: Utilisa a sn1per para reconocimiento"""
    subprocess.run(["sniper", "-t", url], check=True)

@app.command()
def send_request(url:str):
    """ Envía una solicitud GET y guarda el tiempo de respuesta"""
    start_time = time.time()
    response = requests.get(url)
    end_time = time.time()
    return print (f"request simple a:", response, end_time - start_time)


@app.command()
def time_based_enumeration(url:str):
    send_request(url)
    """Realiza la enumeración basada en el tiempo de respuesta"""
    responses = []
    for i in range(10):  # realiza 10 solicitudes para obtener una muestra
        response, response_time = send_request(url)
        responses.append(response_time)
        time.sleep(1)  # espera 1 segundo antes de enviar la siguiente solicitud
    for i, response_time in enumerate(responses):
        print(f"Respuesta {i}: {response_time}")
    # Si hay un patrón en los tiempos de respuesta, puede intentar explotarlo mediante técnicas de enumeración adicionales
    print (time_based_enumeration(url))

if __name__== "__main__":
    app()