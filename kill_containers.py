# script to kill all containers and remove all unused networks
import docker

client = docker.from_env()
containers = client.containers.list()
for container in containers:
    container.kill()
    container.remove()

client.networks.prune()