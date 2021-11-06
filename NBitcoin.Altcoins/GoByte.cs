using NBitcoin.Crypto;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;
using System;
using System.IO;
using System.Linq;

namespace NBitcoin.Altcoins
{
	// Reference: https://github.com/gobytecoin/gobyte/blob/master/src/chainparams.cpp
	public class GoByte : NetworkSetBase
	{
		public static GoByte Instance { get; } = new GoByte();

		public override string CryptoCode => "GBX";

		private GoByte()
		{

		}

		public class GoByteConsensusFactory : ConsensusFactory
		{
			private GoByteConsensusFactory()
			{
			}

			// ReSharper disable once MemberHidesStaticFromOuterClass
			public static GoByteConsensusFactory Instance { get; } = new GoByteConsensusFactory();

			public override BlockHeader CreateBlockHeader()
			{
				return new GoByteBlockHeader();
			}

			public override Block CreateBlock()
			{
				return new GoByteBlock(new GoByteBlockHeader());
			}

			public override Transaction CreateTransaction()
			{
				return new GoByteTransaction();
			}
		}

#pragma warning disable CS0618 // Type or member is obsolete
		public class GoByteBlockHeader : BlockHeader
		{
			// https://github.com/dashpay/dash/blob/e596762ca22d703a79c6880a9d3edb1c7c972fd3/src/primitives/block.cpp#L13
			//static byte[] CalculateHash(byte[] data, int offset, int count)
			//{
			//	return new HashX11.X11().ComputeBytes(data.Skip(offset).Take(count).ToArray());
			//}

			//protected override HashStreamBase CreateHashStream()
			//{
			//	return BufferedHashStream.CreateFrom(CalculateHash, 80);
			//}
			public override uint256 GetPoWHash()
            {
                //TODO: Implement here
                throw new NotSupportedException();
            }
        }
		}

		/// <summary>
		/// Transactions with version >= 3 have a special transaction type in the version code
		/// https://docs.dash.org/en/stable/merchants/technical.html#v0-13-0-integration-notes
		/// 0.14 will add more types: https://github.com/dashpay/dips/blob/master/dip-0002-special-transactions.md
		/// </summary>
		public enum GoByteTransactionType
		{
			StandardTransaction = 0,
			MasternodeRegistration = 1,
			UpdateMasternodeService = 2,
			UpdateMasternodeOperator = 3,
			MasternodeRevocation = 4,
			MasternodeListMerkleProof = 5,
			QuorumCommitment = 6
		}

		public abstract class SpecialTransaction
		{
			protected SpecialTransaction(byte[] extraPayload)
			{
				data = new BinaryReader(new MemoryStream(extraPayload));
				Version = data.ReadUInt16();
			}

			protected readonly BinaryReader data;
			/// <summary>
			/// Version number. Currently set to 1 for all GoByteTransactionTypes
			/// </summary>
			public ushort Version { get; set; }

			/// <summary>
			/// https://github.com/dashevo/dashcore-lib/blob/master/lib/constants/index.js
			/// </summary>
			public const int PUBKEY_ID_SIZE = 20;
			public const int COMPACT_SIGNATURE_SIZE = 65;
			public const int SHA256_HASH_SIZE = 32;
			public const int BLS_PUBLIC_KEY_SIZE = 48;
			public const int BLS_SIGNATURE_SIZE = 96;
			public const int IpAddressLength = 16;

			protected void MakeSureWeAreAtEndOfPayload()
			{
				if (data.BaseStream.Position < data.BaseStream.Length)
					throw new Exception(
						"Failed to parse payload: raw payload is bigger than expected (pos=" +
						data.BaseStream.Position + ", len=" + data.BaseStream.Length + ")");
			}
		}

		/// <summary>
		/// https://github.com/dashpay/dips/blob/master/dip-0003.md
		/// </summary>
		public class ProviderRegistrationTransaction : SpecialTransaction
		{
			public ProviderRegistrationTransaction(byte[] extraPayload) : base(extraPayload)
			{
				Type = data.ReadUInt16();
				Mode = data.ReadUInt16();
				CollateralHash = new uint256(data.ReadBytes(SHA256_HASH_SIZE), true);
				CollateralIndex = data.ReadUInt32();
				IpAddress = data.ReadBytes(IpAddressLength);
				Port = BitConverter.ToUInt16(data.ReadBytes(2).Reverse().ToArray(), 0);
				KeyIdOwner = new uint160(data.ReadBytes(PUBKEY_ID_SIZE), true);
				KeyIdOperator = data.ReadBytes(BLS_PUBLIC_KEY_SIZE);
				KeyIdVoting = new uint160(data.ReadBytes(PUBKEY_ID_SIZE), true);
				OperatorReward = data.ReadUInt16();
				var bs = new BitcoinStream(data.BaseStream, false);
				bs.ReadWriteAsVarInt(ref ScriptPayoutSize);
				ScriptPayout = new Script(data.ReadBytes((int)ScriptPayoutSize));
				InputsHash = new uint256(data.ReadBytes(SHA256_HASH_SIZE), true);
				bs.ReadWriteAsVarInt(ref PayloadSigSize);
				PayloadSig = data.ReadBytes((int)PayloadSigSize);
				MakeSureWeAreAtEndOfPayload();
			}

			public ushort Type { get; set; }
			public ushort Mode { get; set; }
			public uint256 CollateralHash { get; set; }
			public uint CollateralIndex { get; set; }
			public byte[] IpAddress { get; set; }
			public ushort Port { get; set; }
			public uint160 KeyIdOwner { get; set; }
			public byte[] KeyIdOperator { get; set; }
			public uint160 KeyIdVoting { get; set; }
			public ushort OperatorReward { get; set; }
			public uint ScriptPayoutSize;
			public Script ScriptPayout { get; set; }
			public uint256 InputsHash { get; set; }
			public uint PayloadSigSize;
			public byte[] PayloadSig { get; set; }
		}

		public class ProviderUpdateServiceTransaction : SpecialTransaction
		{
			public ProviderUpdateServiceTransaction(byte[] extraPayload) : base(extraPayload)
			{
				ProTXHash = new uint256(data.ReadBytes(SHA256_HASH_SIZE), true);
				IpAddress = data.ReadBytes(IpAddressLength);
				Port = BitConverter.ToUInt16(data.ReadBytes(2).Reverse().ToArray(), 0);
				var bs = new BitcoinStream(data.BaseStream, false);
				bs.ReadWriteAsVarInt(ref ScriptOperatorPayoutSize);
				ScriptOperatorPayout = new Script(data.ReadBytes((int)ScriptOperatorPayoutSize));
				InputsHash = new uint256(data.ReadBytes(SHA256_HASH_SIZE), true);
				PayloadSig = data.ReadBytes(BLS_SIGNATURE_SIZE);
				MakeSureWeAreAtEndOfPayload();
			}

			public uint256 ProTXHash { get; set; }
			public byte[] IpAddress { get; set; }
			public ushort Port { get; set; }
			public uint ScriptOperatorPayoutSize;
			public Script ScriptOperatorPayout { get; set; }
			public uint256 InputsHash { get; set; }
			public byte[] PayloadSig { get; set; }
		}

		public class ProviderUpdateRegistrarTransaction : SpecialTransaction
		{
			public ProviderUpdateRegistrarTransaction(byte[] extraPayload) : base(extraPayload)
			{
				ProTXHash = new uint256(data.ReadBytes(SHA256_HASH_SIZE), true);
				Mode = data.ReadUInt16();
				PubKeyOperator = data.ReadBytes(BLS_PUBLIC_KEY_SIZE);
				KeyIdVoting = new uint160(data.ReadBytes(PUBKEY_ID_SIZE), true);
				var bs = new BitcoinStream(data.BaseStream, false);
				bs.ReadWriteAsVarInt(ref ScriptPayoutSize);
				ScriptPayout = new Script(data.ReadBytes((int)ScriptPayoutSize));
				InputsHash = new uint256(data.ReadBytes(SHA256_HASH_SIZE), true);
				if (data.BaseStream.Position < data.BaseStream.Length)
				{
					bs.ReadWriteAsVarInt(ref PayloadSigSize);
					PayloadSig = data.ReadBytes((int)PayloadSigSize);
				}
				else
					PayloadSig = new byte[0];
				MakeSureWeAreAtEndOfPayload();
			}

			public uint256 ProTXHash { get; set; }
			public ushort Mode { get; set; }
			public byte[] PubKeyOperator { get; set; }
			public uint160 KeyIdVoting { get; set; }
			public uint ScriptPayoutSize;
			public Script ScriptPayout { get; set; }
			public uint256 InputsHash { get; set; }
			public uint PayloadSigSize;
			public byte[] PayloadSig { get; set; }
		}

		public class ProviderUpdateRevocationTransaction : SpecialTransaction
		{
			public ProviderUpdateRevocationTransaction(byte[] extraPayload) : base(extraPayload)
			{
				ProTXHash = new uint256(data.ReadBytes(SHA256_HASH_SIZE), true);
				Reason = data.ReadUInt16();
				InputsHash = new uint256(data.ReadBytes(SHA256_HASH_SIZE), true);
				PayloadSig = data.ReadBytes(BLS_SIGNATURE_SIZE);
				MakeSureWeAreAtEndOfPayload();
			}

			public uint256 ProTXHash { get; set; }
			public ushort Reason { get; set; }
			public uint256 InputsHash { get; set; }
			public uint PayloadSigSize;
			public byte[] PayloadSig { get; set; }
		}

		public abstract class SpecialTransactionWithHeight : SpecialTransaction
		{
			protected SpecialTransactionWithHeight(byte[] extraPayload) : base(extraPayload)
			{
				Height = data.ReadUInt32();
			}

			/// <summary>
			/// Height of the block
			/// </summary>
			public uint Height { get; set; }
		}

		/// <summary>
		/// For GoByteTransactionType.MasternodeListMerkleProof
		/// https://github.com/dashpay/dips/blob/master/dip-0004.md
		/// Only needs deserialization here, ExtraPayload can still be serialized
		/// </summary>
		public class CoinbaseSpecialTransaction : SpecialTransactionWithHeight
		{
			public CoinbaseSpecialTransaction(byte[] extraPayload) : base(extraPayload)
			{
				MerkleRootMNList = new uint256(data.ReadBytes(SHA256_HASH_SIZE));
				MakeSureWeAreAtEndOfPayload();
			}

			/// <summary>
			/// Merkle root of the masternode list
			/// </summary>
			public uint256 MerkleRootMNList { get; set; }
		}

		/// <summary>
		/// https://github.com/dashevo/dashcore-lib/blob/master/lib/transaction/payload/commitmenttxpayload.js
		/// </summary>
		public class QuorumCommitmentTransaction : SpecialTransactionWithHeight
		{
			public QuorumCommitmentTransaction(byte[] extraPayload) : base(extraPayload)
			{
				Commitment = new QuorumCommitment(data);
				MakeSureWeAreAtEndOfPayload();
			}

			public QuorumCommitment Commitment { get; set; }
		}

		public class QuorumCommitment
		{
			public QuorumCommitment(BinaryReader data)
			{
				QfcVersion = data.ReadUInt16();
				LlmqType = data.ReadByte();
				QuorumHash = new uint256(data.ReadBytes(SpecialTransaction.SHA256_HASH_SIZE));
				var bs = new BitcoinStream(data.BaseStream, false);
				bs.ReadWriteAsVarInt(ref SignersSize);
				Signers = data.ReadBytes(((int)SignersSize + 7) / 8);
				bs.ReadWriteAsVarInt(ref ValidMembersSize);
				ValidMembers = data.ReadBytes(((int)ValidMembersSize + 7) / 8);
				QuorumPublicKey = data.ReadBytes(SpecialTransaction.BLS_PUBLIC_KEY_SIZE);
				QuorumVvecHash = new uint256(data.ReadBytes(SpecialTransaction.SHA256_HASH_SIZE));
				QuorumSig = data.ReadBytes(SpecialTransaction.BLS_SIGNATURE_SIZE);
				Sig = data.ReadBytes(SpecialTransaction.BLS_SIGNATURE_SIZE);
			}

			public ushort QfcVersion { get; set; }
			public byte LlmqType { get; set; }
			public uint256 QuorumHash { get; set; }
			public uint SignersSize;
			public byte[] Signers { get; set; }
			public uint ValidMembersSize;
			public byte[] ValidMembers { get; set; }
			public byte[] QuorumPublicKey { get; set; }
			public uint256 QuorumVvecHash { get; set; }
			public byte[] QuorumSig { get; set; }
			public byte[] Sig { get; set; }
		}

		/// <summary>
		/// https://docs.dash.org/en/stable/merchants/technical.html#v0-13-0-integration-notes
		/// </summary>
		public class GoByteTransaction : Transaction
		{
			public uint GoByteVersion => Version & 0xffff;
			public GoByteTransactionType GoByteType => (GoByteTransactionType)((Version >> 16) & 0xffff);
			public byte[] ExtraPayload = new byte[0];
			public ProviderRegistrationTransaction ProRegTx =>
				GoByteType == GoByteTransactionType.MasternodeRegistration
					? new ProviderRegistrationTransaction(ExtraPayload)
					: null;
			public ProviderUpdateServiceTransaction ProUpServTx =>
				GoByteType == GoByteTransactionType.UpdateMasternodeService
					? new ProviderUpdateServiceTransaction(ExtraPayload)
					: null;
			public ProviderUpdateRegistrarTransaction ProUpRegTx =>
				GoByteType == GoByteTransactionType.UpdateMasternodeOperator
					? new ProviderUpdateRegistrarTransaction(ExtraPayload)
					: null;
			public ProviderUpdateRevocationTransaction ProUpRevTx =>
				GoByteType == GoByteTransactionType.MasternodeRevocation
					? new ProviderUpdateRevocationTransaction(ExtraPayload)
					: null;
			public CoinbaseSpecialTransaction CbTx =>
				GoByteType == GoByteTransactionType.MasternodeListMerkleProof
					? new CoinbaseSpecialTransaction(ExtraPayload)
					: null;
			public QuorumCommitmentTransaction QcTx =>
				GoByteType == GoByteTransactionType.QuorumCommitment
					? new QuorumCommitmentTransaction(ExtraPayload)
					: null;

			public override void ReadWrite(BitcoinStream stream)
			{
				base.ReadWrite(stream);
				// Support for GoByte 0.13 extraPayload for Special Transactions
				// https://github.com/dashpay/dips/blob/master/dip-0002-special-transactions.md
				if (GoByteVersion >= 3 && GoByteType != GoByteTransactionType.StandardTransaction)
				{
					// Extra payload size is VarInt
					uint extraPayloadSize = (uint)ExtraPayload.Length;
					stream.ReadWriteAsVarInt(ref extraPayloadSize);
					if (ExtraPayload.Length != extraPayloadSize)
						ExtraPayload = new byte[extraPayloadSize];
					stream.ReadWrite(ref ExtraPayload);
				}
			}
		}

		public class GoByteBlock : Block
		{
			public GoByteBlock(GoByteBlockHeader h) : base(h)
			{
			}
			public override ConsensusFactory GetConsensusFactory()
			{
				return Instance.Mainnet.Consensus.ConsensusFactory;
			}

			public override string ToString()
			{
				return "GoByteBlock " + Header + ", Height=" + GetCoinbaseHeight() +
					", Version=" + Header.Version + ", Txs=" + Transactions.Count;
			}
		}
#pragma warning restore CS0618 // Type or member is obsolete

		protected override void PostInit()
		{
			RegisterDefaultCookiePath("GoByteCore");
		}

		protected override NetworkBuilder CreateMainnet()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 210240,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				BIP34Hash = new uint256("0x00000c8a1ff01bae3f3875c81cb14115429af5744643b34b4ad1cbb7d2d59ca2"),
        PowLimit = new Target(new uint256("0x00000fffff000000000000000000000000000000000000000000000000000000")),
				MinimumChainWork = new uint256("0x000000000000000000000000000000000000000000000000087f3c61c6af5e6a"),
				PowTargetTimespan = TimeSpan.FromSeconds(60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(2.5 * 60),
				PowAllowMinDifficultyBlocks = false,
				CoinbaseMaturity = 100,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 1916,
				MinerConfirmationWindow = 2016,
				ConsensusFactory = GoByteConsensusFactory.Instance,
				SupportSegwit = false
			})
      .SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 38 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 10 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 198 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("gobyte"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("gobyte"))
			.SetUriScheme("gobyte")
			.SetMagic(0xD4C3B21A)
			.SetPort(12455)
			.SetRPCPort(12454)
			.SetMaxP2PVersion(70209)
			.SetName("gobyte-main")
			.AddAlias("gobyte-mainnet")
			.AddDNSSeeds(new[]
      {
				new  DNSSeedData("seed1.gobyte.network", "seed1.gobyte.network"),
				new  DNSSeedData("seed2.gobyte.network", "seed2.gobyte.network"),
				new  DNSSeedData("seed3.gobyte.network", "seed3.gobyte.network"),
				new  DNSSeedData("seed4.gobyte.network", "seed4.gobyte.network"),
				new  DNSSeedData("seed5.gobyte.network", "seed5.gobyte.network"),
				new  DNSSeedData("seed6.gobyte.network", "seed6.gobyte.network"),
				new  DNSSeedData("seed7.gobyte.network", "seed7.gobyte.network"),
				new  DNSSeedData("seed8.gobyte.network", "seed8.gobyte.network"),
				new  DNSSeedData("seed9.gobyte.network", "seed9.gobyte.network"),
				new  DNSSeedData("seed10.gobyte.network", "seed10.gobyte.network")
			}) // done
			.AddSeeds(new NetworkAddress[0])
			.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000219f39f283f43185a0ef69cba1702151ab0cf02454a57e1039dabcc19d719adc00b60d5af0ff0f1e6fe618000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4204ffff001d01043a5468652053746172204d616c61797369612031377468204e6f76656d626572203230313720476f427974652047656e65736973205265626f726effffffff0100f2052a010000004341043e5a5fbfbb2caa5f4b7c8fd24d890d6c244de254d579b5ba629f64c1b48275f59e0e1c834a60f6ffb4aaa022aaa4866434ca729a12465f80618fb2070045cb16ac00000000");
			return builder;
		}

		protected override NetworkBuilder CreateTestnet()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 210240,
				MajorityEnforceBlockUpgrade = 51,
				MajorityRejectBlockOutdated = 75,
				MajorityWindow = 100,
        BIP34Hash = new uint256("0x0000039db8b789064e2370998cdd0a914cf516869796fe5da5ae095a94eaa812"),
				PowLimit = new Target(new uint256("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				MinimumChainWork = new uint256("0x000000000000000000000000000000000000000000000000000000012dcc19a7"),
				PowTargetTimespan = TimeSpan.FromSeconds(60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(2.5 * 60),
				PowAllowMinDifficultyBlocks = true,
				CoinbaseMaturity = 100,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 1512,
				MinerConfirmationWindow = 2016,
				ConsensusFactory = GoByteConsensusFactory.Instance,
				SupportSegwit = false
			})
      .SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 112 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 20 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 239 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x35, 0x87, 0xCF })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x35, 0x83, 0x94 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("tgobyte"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("tgobyte"))
			.SetMagic(0x7AB32BD1)
			.SetPort(13455)
			.SetRPCPort(13454)
			.SetMaxP2PVersion(70209)
		   .SetName("gobyte-test")
		   .AddAlias("gobyte-testnet")
		   .SetUriScheme("gobyte")
		   .AddDNSSeeds(new[]
       {
			   new DNSSeedData("gobyte.network",  "testnet-dns.gobyte.network"),
			   new DNSSeedData("gobyte.network",  "testnet2-dns.gobyte.network")
		   })
		   .AddSeeds(new NetworkAddress[0])
		   .SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000219f39f283f43185a0ef69cba1702151ab0cf02454a57e1039dabcc19d719adc20de0b5af0ff0f1ebbc02d000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4204ffff001d01043a5468652053746172204d616c61797369612031377468204e6f76656d626572203230313720476f427974652047656e65736973205265626f726effffffff0100f2052a010000004341043e5a5fbfbb2caa5f4b7c8fd24d890d6c244de254d579b5ba629f64c1b48275f59e0e1c834a60f6ffb4aaa022aaa4866434ca729a12465f80618fb2070045cb16ac00000000");
			return builder;
		}

		protected override NetworkBuilder CreateRegtest()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 150,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				BIP34Hash = new uint256(),
        PowLimit = new Target(new uint256()),
				MinimumChainWork = new uint256("0x000000000000000000000000000000000000000000000000000000000000000"),
				PowTargetTimespan = TimeSpan.FromSeconds(24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(2.5 * 60),
				PowAllowMinDifficultyBlocks = true,
				CoinbaseMaturity = 100,
				PowNoRetargeting = true,
				RuleChangeActivationThreshold = 108,
				MinerConfirmationWindow = 144,
				ConsensusFactory = GoByteConsensusFactory.Instance,
				SupportSegwit = false
			})
      .SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 112 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 20 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 240 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x35, 0x87, 0xCF })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x35, 0x83, 0x94 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("tgobyte"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("tgobyte"))
			.SetMagic(0x7BD5B3A1)
			.SetPort(13565)
			.SetRPCPort(13564)
			.SetMaxP2PVersion(70209)
			.SetName("gobyte-reg")
			.AddAlias("gobyte-regtest")
			.SetUriScheme("gobyte")
			.AddDNSSeeds(new DNSSeedData[0])
			.AddSeeds(new NetworkAddress[0])
			.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000219f39f283f43185a0ef69cba1702151ab0cf02454a57e1039dabcc19d719adcbcdd0b5af0ff0f1e63c00d000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4204ffff001d01043a5468652053746172204d616c61797369612031377468204e6f76656d626572203230313720476f427974652047656e65736973205265626f726effffffff0100f2052a010000004341043e5a5fbfbb2caa5f4b7c8fd24d890d6c244de254d579b5ba629f64c1b48275f59e0e1c834a60f6ffb4aaa022aaa4866434ca729a12465f80618fb2070045cb16ac00000000");
			return builder;
		}
	}
}
