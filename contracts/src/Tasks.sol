// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title Tasks — tarefas do CU Golf com implementação nativa em Solidity
/// @notice Cada tarefa tem (a) um gerador de inputs a partir de uma seed e (b) a resposta esperada,
///         calculada com a mesma aritmética de 64 bits com wraparound da VM. O programa sBPF do
///         jogador recebe o input em r1 (região INPUT) e devolve a resposta em r0.
library Tasks {
    uint256 internal constant NUM_TASKS = 5;

    uint256 internal constant FIB = 0; // [u64 n]      -> fib(n) mod 2^64
    uint256 internal constant POPCOUNT = 1; // [u64 x]      -> bits 1 em x
    uint256 internal constant ISQRT = 2; // [u64 x]      -> floor(sqrt(x))
    uint256 internal constant MAX8 = 3; // [u64 x 8]    -> máximo sem sinal
    uint256 internal constant GCD = 4; // [u64 a][u64 b] -> mdc(a, b), mdc(a, 0) = a

    function name(uint256 task) internal pure returns (string memory) {
        if (task == FIB) return "fib";
        if (task == POPCOUNT) return "popcount";
        if (task == ISQRT) return "isqrt";
        if (task == MAX8) return "max8";
        if (task == GCD) return "gcd";
        return "?";
    }

    /// @notice Input determinístico nº `k` para a tarefa, derivado da seed.
    function inputFor(uint256 task, bytes32 seed, uint256 k) internal pure returns (bytes memory) {
        bytes32 h = keccak256(abi.encode(seed, k));
        if (task == FIB) return _le64(uint64(uint8(h[0]))); // n em [0, 255]
        if (task == POPCOUNT) return _le64(uint64(uint256(h)));
        if (task == ISQRT) {
            // alterna valores grandes e pequenos para cobrir os dois regimes
            uint64 x = uint64(uint256(h));
            if (k % 2 == 1) x >>= 40;
            return _le64(x);
        }
        if (task == MAX8) {
            bytes memory out;
            for (uint256 i = 0; i < 8; i++) {
                out = bytes.concat(out, _le64(uint64(uint256(keccak256(abi.encode(h, i))))));
            }
            return out;
        }
        if (task == GCD) {
            uint64 a = uint64(uint256(h));
            uint64 b = uint64(uint256(h) >> 64);
            // a cada 4 inputs um deles tem fator comum grande, para o mdc não ser quase sempre 1
            if (k % 4 == 3) {
                uint64 g = uint64(uint256(h) >> 128) | 1;
                a = uint64(uint256(a) * g);
                b = uint64(uint256(b) * g);
            }
            return bytes.concat(_le64(a), _le64(b));
        }
        revert("task");
    }

    /// @notice Resposta nativa. `input` tem o layout descrito nas constantes acima.
    function expected(uint256 task, bytes memory input) internal pure returns (uint64) {
        unchecked {
            if (task == FIB) {
                uint64 n = _u64(input, 0);
                uint64 a = 0;
                uint64 b = 1;
                for (uint64 i = 0; i < n; i++) {
                    (a, b) = (b, a + b); // wraparound em 64 bits
                }
                return a;
            }
            if (task == POPCOUNT) {
                uint64 x = _u64(input, 0);
                uint64 c = 0;
                while (x != 0) {
                    c += x & 1;
                    x >>= 1;
                }
                return c;
            }
            if (task == ISQRT) {
                uint256 x = _u64(input, 0);
                if (x == 0) return 0;
                uint256 r = x;
                uint256 y = (x + 1) / 2;
                while (y < r) {
                    r = y;
                    y = (y + x / y) / 2;
                }
                return uint64(r);
            }
            if (task == MAX8) {
                uint64 m = 0;
                for (uint256 i = 0; i < 8; i++) {
                    uint64 v = _u64(input, i * 8);
                    if (v > m) m = v;
                }
                return m;
            }
            if (task == GCD) {
                uint64 a = _u64(input, 0);
                uint64 b = _u64(input, 8);
                while (b != 0) {
                    (a, b) = (b, a % b);
                }
                return a;
            }
            revert("task");
        }
    }

    function _u64(bytes memory b, uint256 off) private pure returns (uint64 v) {
        for (uint256 i = 0; i < 8; i++) {
            v |= uint64(uint8(b[off + i])) << uint64(8 * i);
        }
    }

    function _le64(uint64 x) private pure returns (bytes memory) {
        x = ((x & 0x00000000ffffffff) << 32) | (x >> 32);
        x = ((x & 0x0000ffff0000ffff) << 16) | ((x >> 16) & 0x0000ffff0000ffff);
        x = ((x & 0x00ff00ff00ff00ff) << 8) | ((x >> 8) & 0x00ff00ff00ff00ff);
        return abi.encodePacked(bytes8(x));
    }
}
