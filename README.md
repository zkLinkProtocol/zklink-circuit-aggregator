# zkLink Circuit Aggregator

## Introduction

The zkLink Circuit Aggregator integrates several key components to facilitate the seamless aggregation of cryptographic proofs within the zkLink protocol. 
This process is critical for maintaining the integrity and efficiency of the verification processes within the zkLink protocol's circuits interoperability solution.


## Components

- `FinalAggregationCircuit`: The FinalAggregationCircuit serves as the ultimate step in the proof aggregation process. It is responsible for synthesizing the block and oracle aggregation proofs into one cohesive final proof (final_proof). .
- `BlockAggregationCircuit`: The BlockAggregationCircuit focuses on the aggregation of proofs for individual transaction blocks. It generates a composite proof that encompasses all transactions within a block.
- `OracleAggregationCircuit`: The OracleAggregationCircuit consolidates proofs from various oracle size proof.

## Contributing
Contributions are welcome! For any enhancements, fixes, or feature requests, please follow our contribution guidelines in CONTRIBUTING.md.

## Support
For any technical support or questions, please open an issue or contact us at zk.link.

## License
This project is open-sourced under the MIT License. See LICENSE for more details.
