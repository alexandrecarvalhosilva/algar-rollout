# teste rápido de acesso
ansible -i inventory/hosts.ini linux_all -m ping -o

# rodar auditoria completa
ansible-playbook -i inventory/hosts.ini scripts/audit.yml --check --diff

# filtrar só produção na 1ª passada
ansible-playbook -i inventory/hosts.ini scripts/audit.yml --limit env_prd --check --diff
