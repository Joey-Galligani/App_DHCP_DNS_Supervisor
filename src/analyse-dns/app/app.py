### Librairies ### 

import requests
import os
import time
from typing import Any

### Fonctions ### 

class Filtre:
    def __init__(self, url):
        """
        self.data (dict(str)) : trame récupérée sur l'api 
        """
        response = requests.get(url)
        if response.status_code == 200:
            self.data = response.json()
        else:
            self.data = None
    
    ###   parser le fichier   ##############################################################################################
    
    def parse_json_file_ID(self):
        """
        Returns:
            (str) : ID de la trame DNS
        """
        return self.data['ID']

    def parse_json_file_time(self):
        """
        Returns:
            (str): timestamp de la requete 
        """
        return self.data['timestamp']

    def parse_json_file_macsrc(self):
        """
        Returns:
            (str): adresse mac source de la requete DNS 
        """
        return self.data['macsrc']

    def parse_json_file_macdst(self):
        """
        Returns:
            (str): adresse mac de destination de la requete DNS 
        """
        return self.data['macdst']

    def parse_json_file_ipsrc(self):
        """
        Returns:
            (str): adresse ip source de la requete DNS 
        """
        return self.data['ipsrc']

    def parse_json_file_ipdst(self):
        """
        Returns:
            (str): adresse ip de destination de la requete DNS 
        """
        return self.data['ipdst']

    def parse_json_file_rcode(self):
        """
        Returns:
            (str): code d'erreur de la requete DNS 
        """
        return self.data['dns']['rcode']

    def parse_json_file_dn(self):
        """
        Returns:
            (str): nom de domaine 
        """
        if len(self.data['dns']['answer']) > 1:
            return self.data['dns']['answer']
        else:
            return ''

    ###    TLD    #########################################################################################################################################################

    def extraire_tld(self, dn: str):
        """
        Args:
            dn (str): nom de domaine 

        Returns:
            extraction.suffix (str): tld du nom de domaine
        """
        extraction = dn.split('.')[-1]
        return extraction
    
    
    def detect_bad_tld_fct(self, file_bad_tld: str, tld_resultat: str):
        """
        Args:
            file_bad_tld (str): chemin vers le fichier des tld dangereux
            tld_resultat (str): tld du nom de domaine dans la requete dns

        Returns:
            state_tld (str): etat du tld du nom de domaine safe ou malicieux 
        """
        state_tld = 'Safe'
        with open(file_bad_tld) as bad_tlds:
            for line in bad_tlds:
                if tld_resultat in line:
                    state_tld = 'Dangerous'
                    return state_tld
        return state_tld
    
    def create_post_alert_tld(self, tld_resultat:str, detect_bad_tld:str, url:str):
        """
        Args:
            tld_resultat (str): tld du nom de domaine
            detect_bad_tld (str): etat du tld safe ou dangereux

        Returns:
            response.text (str): requête post de l'alerte sous forme json
        """
        data = {
            "type":"tld",
            "id":id,
            "info":[{"TLD": tld_resultat,
            "state": detect_bad_tld,
            "ip": ipdst}]
        }
        
        if detect_bad_tld == 'Dangerous':
            response = requests.post(url, data=data)
            return response.text
    
    ### Domain Name ######################################################################################################################################################################
    
    def detect_bad_domain_name(self, file_bad_domain: str, dn: str, dn_forbidden_cli: list[str]):
        """
        Args:
            file_bad_domain (str): chemin vers le fichier des noms de domaine malicious
            dn (str): nom de domaine
            dn_forbidden_cli (liste[str]): liste des noms de domaine choisis par le client comme a surveiller 

        Returns:
            state_dn (str): etat du nom domain malicious ou clean 
        """
        state_dn = 'Clean'
        for i in range (len(dn_forbidden_cli)):
            if dn == dn_forbidden_cli[i]:
                state_dn = 'Forbidden'
        with open(file_bad_domain) as bad_domain_names:
            for line in bad_domain_names:
                if dn in line:
                    state_dn = 'Malicious'
                    return state_dn
        return state_dn

        
    def get_liste_dn_forbidden(self, url:str):
        """
        Returns:
            liste_dn_forbidden (liste[str]): liste des noms de domaine a surveiller choisis par le client
        """
        response = requests.get(url)
        if response.status_code == 200:
            data_superv = response.json()
            return data_superv['dn']
        else:
            return []

    def create_post_alert_dn(self, dn:str, detect_bad_dn:str, url:str):
        """
        Args:
            dn (str): nom de domaine
            detect_bad_dn (str): etat de nom de domaine malicious ou clean

        Returns:
            response.text (str): requête post de l'alerte sous forme json
        """       

        data = {
            "type": "domain_name",
            "id": id,
            "info":[{"domain_name": dn,
            "state": detect_bad_dn,
            "ip": ipdst}]
        }
        
        data2 = {
            "type":"domain_name_cli",
            "id":id,
            "info":[{"domain_name:": dn,
            "state": detect_bad_dn,
            "ip": ipdst,
            "message": "Nom de domaine interdit par le client"}]
        }
        if detect_bad_dn == 'Malicious':
            response = requests.post(url, data=data)
            return response.text
        if detect_bad_dn == 'Forbidden':
            response = requests.post(url, data=data2)
            return response.text
    
    ####    RCODE      #################################################################################################################

    def idntification_rcode(self, rcode: str):
        """
        Args:
            rcode (str): code d'erreur de la requete dns 

        Returns:
            msg (str): type de l'erreur 
            commentaire (str): description de l'erreur 
        """
        rcode = int(rcode)
        if rcode == 0 :
            msg  = 'NOERROR'
            commentaire = 'La requête a été traitée avec succès, et la réponse contient les informations demandées'
            return msg, commentaire
        elif rcode == 1 :
            msg  = 'FORMERR'
            commentaire = 'La requête DNS a un format incorrect'
            return msg, commentaire
        elif rcode == 2 :
            msg = 'SERVFAIL'
            commentaire = "Le serveur DNS n'a pas pu traiter la requête en raison d'une erreur interne"
            return msg, commentaire
        elif rcode == 3 :
            msg = 'NXDOMAIN'
            commentaire = "Le nom de domaine spécifié dans la requête DNS n'existe pas"
            return msg, commentaire
        elif rcode == 4 :
            msg = 'NOTIMP'
            commentaire = "Le type de requête spécifié n'est pas pris en charge par le serveur DNS"
            return msg, commentaire
        elif rcode == 5 :
            msg = 'REFUSED'
            commentaire = 'Le serveur DNS a refusé la requête'
            return msg, commentaire
        elif rcode == 6 :
            msg = 'YXDOMAIN' 
            commentaire = 'Le nom de domaine spécifié existe déjà'
            return msg, commentaire
        elif rcode == 7 :
            msg = "XRRSET"
            commentaire = "L'enregistrement (Resource Record Set) spécifié existe déjà ou n'existe pas "
            return msg, commentaire
        elif rcode == 8 :
            msg = 'NOTAUTH'
            commentaire = "Le serveur DNS n'est pas autorisé à effectuer la requête"
            return msg, commentaire 
        elif rcode == 9 :
            msg = 'NOTZONE'
            commentaire = " La requête ne concerne pas la zone où le serveur DNS a autorité"
            return msg, commentaire
        elif rcode >= 10 : 
            msg = 'RESERVED'
            commentaire = "NO COMMENT"
            return msg, commentaire
        
    def create_post_alert_rcode(self, rcode:str, type_rcode:str, com_rcode:str, url:str):
        """
        Args:
            rcode (str): code d'erreur
            type_rcode (str): type d'erreur
            com_rcode (str): description de l'erreur
            url_alert (str): url de l'api pour poster l'alerte

        Returns:
            response.text (str): requête post de l'alerte sous forme json
        """
        
        data = {
            "type":"rcode",
            "id":id,
            "info":[{"code": rcode,
            "type": type_rcode,
            "comment": com_rcode}]
        }
        response = requests.post(url, data=data)
        return response.text
    
    ### Statistiques DNS   #######################################################################################################################################
    
    def create_post_stat(self, tld_resultat:str, dn:str, ipsrc:str, ipdst:str, macsrc:str, macdst:str, time:str, id:int, url:str):
        """
        Args:
            tld_resultat (str): tld du nom de domaine
            dn (str): nom de domaine
            ipsrc (str): adresse ip source de la requete dns 
            ipdst (str): adresse ip de destination de la requete dns 
            macsrc (str): adresse mac source de la requete dns 
            macdst (str): adresse mac destination de la requete dns 
            time (str): timestamp de la requete dns 
            url_analyse (str): url de l'api pour poster les statistiques
            id (str): id de la trame

        Returns:
            response.text (str): requête post des statistiques dns sous forme json
        """
        
        data = {
            "ID": id,
            "ipsrc": ipsrc,
            "ipdst": ipdst,
            "time": time,
            "domain-name": dn,
            "tld": tld_resultat
        }
        response = requests.post(url, data=data)
        return response.text

    ### SEREUR DNS LOCAL ##########################################################################################################################################

    def add_local_srv():
        url = 'http://localhost:8000/entry/dns'
        response = requests.get(url)
        liste_srv=[]
        liste_srv.append(response.json()['ip'])
        return liste_srv
    
    def detect_no_local_srv(liste_srv, ipsrc):
        if ipsrc not in liste_srv :
            url = 'http://localhost:8000/alert/dns'
            data= {
                "type" : "nolocalsrv",
                "id" : id,
                "info": [{"ipsrv":ipdst}]
            }
            response = requests.post(url, data=data)
            return response.json()
        else :
            return "Serveur DNS Local détecté"
        
    
if __name__ == '__main__':
    API_SERV = os.getenv('API_SERV')
    while True:
        frame = Filtre(API_SERV+'/analyse/dns')

        if frame.data != None:

            id = frame.parse_json_file_ID()
            # print("ID : ", id)
            
            timestamp = frame.parse_json_file_time()
            # print("time :",timestamp)

            macsrc = frame.parse_json_file_macsrc()
            # print("mac source :", macsrc)

            macdst = frame.parse_json_file_macdst()
            # print("mac destination :", macdst)

            ipsrc = frame.parse_json_file_ipsrc()
            # print("ip source : ", ipsrc)

            ipdst = frame.parse_json_file_ipdst()
            # print("ip destination :", ipdst)

            rcode = frame.parse_json_file_rcode()
            # print("code erreur : ", rcode)

            dn = frame.parse_json_file_dn()
            # print("Nom de Domaine : ", dn)

            tld_resultat = frame.extraire_tld(dn)
            # print("TLD : ", tld_resultat)

            type_rcode, com_rcode = frame.idntification_rcode(rcode)
            # print('Type Rcode:', type_rcode)
            # print('Commentaire Rcode:', com_rcode)

            dn_forbidden_cli = frame.get_liste_dn_forbidden(API_SERV+'/alert/dns')
            detect_bad_dn = frame.detect_bad_domain_name('./bad_domains.txt', dn, dn_forbidden_cli)
            detect_bad_tld = frame.detect_bad_tld_fct('./bad-tld.txt', tld_resultat)
            # print('The domain name is', detect_bad_dn)
            # print('The TLD is', detect_bad_tld)

            alert_dn = frame.create_post_alert_dn(dn, detect_bad_dn, API_SERV+'/alert/dns')
            # print("requete alerte domain name : ",'\n',alert_dn)

            alert_rcode = frame.create_post_alert_rcode(rcode, type_rcode, com_rcode, API_SERV+'/alert/dns')
            # print("requete alerte code erreur : ",'\n',alert_rcode)

            alert_tld = frame.create_post_alert_tld(tld_resultat, detect_bad_tld, API_SERV+'/alert/dns')
            # print("requete alerte TLD : ",'\n', alert_tld)

            stat_dns = frame.create_post_stat(tld_resultat, dn, ipsrc, ipdst, macsrc, macdst, timestamp, id, API_SERV+'/alert/dns')
            # print("requete stats dns : ",'\n',stat_dns)
        else:
            time.sleep(1)

