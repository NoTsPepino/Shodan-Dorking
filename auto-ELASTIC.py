import argparse
import requests

def main(host):
    port = 9200

    indices_url = f"http://{host}:{port}/_cat/indices?v"
    response = requests.get(indices_url)

    if response.status_code == 200:
        print("Índices disponibles:")
        print(response.text)

        index = input("\nIngresa el nombre del index al que deseas acceder: ")
        search_url = f"http://{host}:{port}/{index}/_search?pretty="
        search_query = input("Ingresa la Query de busqueda: ")
        full_search_url = f"{search_url}{search_query}"
        search_response = requests.get(full_search_url)

        if search_response.status_code == 200:
            print("Resultados de la busqueda:")
            print(search_response.text)
        else:
            print("Error al realizar la busqueda.")
    else:
        print("Error al obtener la lista de indices.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Conectar y buscar en Elasticsearch")
    parser.add_argument("-t", "--host", type=str, required=True, help="Host de Elasticsearch")
    args = parser.parse_args()
    
    main(args.host)
