// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include <boost/program_options.hpp>
#include <fstream>
#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include <iostream>
#include <libzeth/circuit_types.hpp>
#include <libzeth/libsnark_helpers/libsnark_helpers.hpp>
#include <libzeth/snarks_alias.hpp>
#include <libzeth/util.hpp>
#include <libzeth/util_api.hpp>
#include <libzeth/zeth.h>
#include <memory>
#include <stdio.h>
#include <string>

// Necessary header to parse the data
#include <libsnark/common/data_structures/merkle_tree.hpp>

// Include the file generated by gRPC
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include "api/aggregator.grpc.pb.h"
#pragma GCC diagnostic pop

// Include the API for the given SNARK
#include "zecaleConfig.h"

#include <libzeth/snarks_api_imports.hpp>

namespace proto = google::protobuf;
namespace po = boost::program_options;

/// The aggregator_server class inherits from the Aggregator service
/// defined in the proto files, and provides an implementation
/// of the service.
class aggregator_server final : public aggregator_proto::Aggregator::Service
{
private:
    libzecale::aggregator_wrapper<CurveA, CurveB, ZETH_NUM_PROOFS> aggregator;

    // The keypair is the result of the setup for the aggregation circuit
    keyPairT<ppT> keypair;

    // The nested verification key is the vk used to verify the nested proofs
    verificationKeyT<ppT> nested_vk;

public:
    explicit aggregator_server(
        libzecale::aggregate_circuit_wrapper<CurveA, CurveB, ZETH_NUM_PROOFS>
            &aggregator,
        keyPairT<ppT> &keypair,
        verificationKeyT<ppT> nested_vk)
        : aggregator(aggregator), keypair(keypair), nested_vk(nested_vk)
    {
    }

    grpc::Status GetVerificationKey(
        grpc::ServerContext *,
        const proto::Empty *,
        aggregator_proto::VerificationKey *response) override
    {
        std::cout << "[ACK] Received the request to get the verification key"
                  << std::endl;
        std::cout << "[DEBUG] Preparing verification key for response..."
                  << std::endl;
        try {
            prepare_verification_key_response<ppT>(this->keypair.vk, response);
        } catch (const std::exception &e) {
            std::cout << "[ERROR] " << e.what() << std::endl;
            return grpc::Status(
                grpc::StatusCode::INVALID_ARGUMENT, grpc::string(e.what()));
        } catch (...) {
            std::cout << "[ERROR] In catch all" << std::endl;
            return grpc::Status(grpc::StatusCode::UNKNOWN, "");
        }

        return grpc::Status::OK;
    }

    grpc::Status GenerateAggregateProof(
        grpc::ServerContext *,
        const proto::Empty *,
        aggregator_proto::ExtendedProof *proof) override
    {
        std::cout
            << "[ACK] Received the request to generate an aggregation proof"
            << std::endl;

        std::cout << "[DEBUG] Pop batch from the pool..." << std::endl;
        // TODO

        std::cout << "[DEBUG] Parse batch and generate inputs..." << std::endl;
        // TODO

        std::cout << "[DEBUG] Generating the proof..." << std::endl;
        extended_proof<ppT> ext_proof = this->aggregator.prove(
            // TODO
        );

        std::cout << "[DEBUG] Displaying the extended proof" << std::endl;
        ext_proof.dump_proof();
        ext_proof.dump_primary_inputs();

        std::cout << "[DEBUG] Preparing response..." << std::endl;
        prepare_proof_response<ppT>(ext_proof, proof);
    }
    catch (const std::exception &e)
    {
        std::cout << "[ERROR] " << e.what() << std::endl;
        return grpc::Status(
            grpc::StatusCode::INVALID_ARGUMENT, grpc::string(e.what()));
    }
    catch (...)
    {
        std::cout << "[ERROR] In catch all" << std::endl;
        return grpc::Status(grpc::StatusCode::UNKNOWN, "");
    }

    return grpc::Status::OK;
}
}
;

std::string get_server_version()
{
    char buffer[100];
    int n;
    // Defined in the zethConfig file
    n = snprintf(
        buffer,
        100,
        "Version %d.%d",
        ZECALE_VERSION_MAJOR,
        ZECALE_VERSION_MINOR);
    if (n < 0) {
        return "Version <Not specified>";
    }
    std::string version(buffer);
    return version;
}

void display_server_start_message()
{
    std::string copyright =
        "Copyright (c) 2015-2020 Clearmatics Technologies Ltd";
    std::string license = "SPDX-License-Identifier: LGPL-3.0+";
    std::string project = "R&D Department: PoC for a privacy preserving "
                          "scalability solution on Ethereum";
    std::string version = get_server_version();
    std::string warning = "**WARNING:** This code is a research-quality proof "
                          "of concept, DO NOT use in production!";

    std::cout << "\n=====================================================\n";
    std::cout << copyright << "\n";
    std::cout << license << "\n";
    std::cout << project << "\n";
    std::cout << version << "\n";
    std::cout << warning << "\n";
    std::cout << "=====================================================\n"
              << std::endl;
}

static void RunServer(
    libzecale::aggregator_wrapper<CurveA, CurveB, ZETH_NUM_PROOFS> &aggregator,
    keyPairT<ppT> &keypair)
{
    // Listen for incoming connections on 0.0.0.0:50052
    std::string server_address("0.0.0.0:50052");

    aggregator_server service(aggregator, keypair);

    grpc::ServerBuilder builder;

    // Listen on the given address without any authentication mechanism.
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

    // Register "service" as the instance through which we'll communicate with
    // clients. In this case it corresponds to an *synchronous* service.
    builder.RegisterService(&service);

    // Finally assemble the server.
    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    std::cout << "[DEBUG] Server listening on " << server_address << std::endl;

    // Wait for the server to shutdown. Note that some other thread must be
    // responsible for shutting down the server for this call to ever return.
    display_server_start_message();
    server->Wait();
}

#ifdef ZKSNARK_GROTH16
static keyPairT<ppT> load_keypair(const std::string &keypair_file)
{
    std::ifstream in(keypair_file, std::ios_base::in | std::ios_base::binary);
    in.exceptions(
        std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);
    return libzeth::mpc_read_keypair<ppT>(in);
}
#endif

int main(int argc, char **argv)
{
    // Options
    po::options_description options("");
    options.add_options()(
        "keypair,k", po::value<std::string>(), "file to load keypair from");
#ifdef DEBUG
    options.add_options()(
        "jr1cs,j",
        po::value<boost::filesystem::path>(),
        "file in which to export the r1cs in json format");
#endif

    auto usage = [&]() {
        std::cout << "Usage:"
                  << "\n"
                  << "  " << argv[0] << " [<options>]\n"
                  << "\n";
        std::cout << options;
        std::cout << std::endl;
    };

    std::string keypair_file;
#ifdef DEBUG
    boost::filesystem::path jr1cs_file;
#endif
    try {
        po::variables_map vm;
        po::store(
            po::command_line_parser(argc, argv).options(options).run(), vm);
        if (vm.count("help")) {
            usage();
            return 0;
        }
        if (vm.count("keypair")) {
            keypair_file = vm["keypair"].as<std::string>();
        }
#ifdef DEBUG
        if (vm.count("jr1cs")) {
            jr1cs_file = vm["jr1cs"].as<boost::filesystem::path>();
        }
#endif
    } catch (po::error &error) {
        std::cerr << " ERROR: " << error.what() << std::endl;
        usage();
        return 1;
    }

    // We inititalize the curve parameters here
    std::cout << "[INFO] Init params of both curves" << std::endl;
    CurveA::init_public_params();
    CurveB::init_public_params();

    libzecale::aggregator_wrapper<CurveA, CurveB, ZETH_NUM_PROOFS> aggregator;
    keyPairT<ppT> keypair = [&keypair_file, &aggregator]() {
        if (!keypair_file.empty()) {
#ifdef ZKSNARK_GROTH16
            std::cout << "[INFO] Loading keypair: " << keypair_file
                      << std::endl;
            return load_keypair(keypair_file);
#else
            std::cout << "Keypair loading not supported in this config"
                      << std::endl;
            exit(1);
#endif
        }

        std::cout << "[INFO] Generate new keypair" << std::endl;
        return aggregator.generate_trusted_setup();
    }();

#ifdef DEBUG
    // Run only if the flag is set
    if (jr1cs_file != "") {
        std::cout << "[DEBUG] Dump R1CS to json file" << std::endl;
        aggregator.dump_constraint_system(jr1cs_file);
    }
#endif

    std::cout << "[INFO] Setup successful, starting the server..." << std::endl;
    RunServer(aggregator, keypair);
    return 0;
}
