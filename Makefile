.PHONY: check-black
check-black:
	black . --check --diff

.PHONY: autoflake
autoflake:
	autoflake --in-place --remove-all-unused-imports --ignore-init-module-imports -r . -c

.PHONY: inspect
inspect: autoflake check-black

.PHONY: image
image:
	python3 build_image.py --config ofrak-core-dev.yml --base --finish

tutorial-image:
	DOCKER_BUILDKIT=1 python3 build_image.py --config ofrak-tutorial.yml --base --finish

tutorial-run:
	make -C ofrak_tutorial run

.PHONY: install_tutorial install_code install_develop
install_tutorial:
	python3 install.py --config ofrak-tutorial.yml --target install

install_core:
	python3 install.py --config ofrak-core-dev.yml --target install

install_develop:
	python3 install.py --config ofrak-dev.yml --target develop

