
.PHONY: setup check test syntax grpc

ZETH_DIR:=../depends/zeth
ZETH_CLIENT_DIR:=$(ZETH_DIR)/client
ZETH_PROTO_DIR:=$(ZETH_DIR)/proto

ZECALE_PROTO_DIR:=../proto
ZECALE_PROTO_FILES:=$(wildcard $(ZECALE_PROTO_DIR)/zecale/api/*.proto)

API_DEST_DIR:=zecale/api
API_OUTPUT:= $(addprefix $(API_DEST_DIR)/, aggregator_pb2.py)

# Create rule to build a grpc file from a source file. Params:
#   1 - .proto file
define grpc_build
  $(API_DEST_DIR)/$(notdir $(basename $1))_pb2.py \
  $(API_DEST_DIR)/$(notdir $(basename $1))_pb2_grpc.py : $(1)
	python -m grpc_tools.protoc -I$(ZETH_PROTO_DIR) -I.. --proto_path $(ZECALE_PROTO_DIR) \
      --python_out=. --grpc_python_out=. --mypy_out=. \
      $(subst $(ZECALE_PROTO_DIR)/,,$1)

endef

$(foreach src,$(ZECALE_PROTO_FILES),$(eval \
  $(call grpc_build,$(src)) \
))


setup:
	pip install -e . --progress-bar off
	pip install -e $(ZETH_CLIENT_DIR) --progress-bar off
	$(MAKE) grpc


grpc: $(API_OUTPUT)
	@# suppress "Nothing to do for ..." warning
	@echo -n


syntax: $(API_OUTPUT)
	flake8 `git ls-files '**.py'`
	mypy -p zecale
	mypy -p tests
	pylint zecale tests


test: $(API_OUTPUT)
	python -m unittest


check: syntax test
