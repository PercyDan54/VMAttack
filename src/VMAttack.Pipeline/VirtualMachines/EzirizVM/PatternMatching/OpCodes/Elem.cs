using System.Collections.Generic;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using VMAttack.Pipeline.VirtualMachines.EzirizVM.Architecture;
using VMAttack.Pipeline.VirtualMachines.EzirizVM.Interfaces;

namespace VMAttack.Pipeline.VirtualMachines.EzirizVM.PatternMatching.OpCodes;

#region Ldelem_Ref

internal record LdelemRef : IOpCodePattern
{
    public IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldarg_0,
        CilOpCodes.Ldfld,
        CilOpCodes.Callvirt,
        CilOpCodes.Call,
        CilOpCodes.Stloc_S,
        CilOpCodes.Ldarg_0,
        CilOpCodes.Ldfld,
        CilOpCodes.Callvirt,
        CilOpCodes.Ldnull,
        CilOpCodes.Callvirt,
        CilOpCodes.Castclass,
        CilOpCodes.Dup,
        CilOpCodes.Ldloc_S,
        CilOpCodes.Callvirt,
        CilOpCodes.Ldflda,
        CilOpCodes.Ldfld,
        CilOpCodes.Callvirt,
        CilOpCodes.Stloc_S,
        CilOpCodes.Callvirt,
        CilOpCodes.Callvirt,
        CilOpCodes.Stloc_S,
        CilOpCodes.Ldarg_0,
        CilOpCodes.Ldfld,
        CilOpCodes.Ldloc_S,
        CilOpCodes.Ldloc_S,
        CilOpCodes.Call,
        CilOpCodes.Callvirt,
        CilOpCodes.Ret
    };

    public CilOpCode CilOpCode => CilOpCodes.Ldelem_Ref;

    public bool Verify(EzirizHandler handler) => true;
}

#endregion

#region Stelem_Ref

internal record StelemRef : IOpCodePattern
{
    public IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldarg_0,
        CilOpCodes.Ldfld,
        CilOpCodes.Callvirt,
        CilOpCodes.Stloc_S,
        CilOpCodes.Ldarg_0,
        CilOpCodes.Ldfld,
        CilOpCodes.Callvirt,
        CilOpCodes.Call,
        CilOpCodes.Stloc_S,
        CilOpCodes.Ldarg_0,
        CilOpCodes.Ldfld,
        CilOpCodes.Callvirt,
        CilOpCodes.Ldnull,
        CilOpCodes.Callvirt,
        CilOpCodes.Castclass,
        CilOpCodes.Dup,
        CilOpCodes.Callvirt,
        CilOpCodes.Callvirt,
        CilOpCodes.Stloc_S,
        CilOpCodes.Ldloc_S,
        CilOpCodes.Ldloc_S,
        CilOpCodes.Callvirt,
        CilOpCodes.Ldloc_S,
        CilOpCodes.Callvirt,
        CilOpCodes.Ldflda,
        CilOpCodes.Ldfld,
        CilOpCodes.Callvirt,
        CilOpCodes.Ret,
    };

    public CilOpCode CilOpCode => CilOpCodes.Stelem_Ref;

    public bool Verify(EzirizHandler handler) => true;

    public bool AllowMultiple => true;
}

#endregion

#region Stelem

internal record Stelem : IOpCodePattern
{
    public IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldarg_0,
        CilOpCodes.Ldfld,
        CilOpCodes.Unbox_Any,
        CilOpCodes.Stloc_S,
        CilOpCodes.Ldtoken,
        CilOpCodes.Call,
        CilOpCodes.Callvirt,
        CilOpCodes.Ldloc_S,
        CilOpCodes.Callvirt,
        CilOpCodes.Stloc_S,
        CilOpCodes.Ldarg_0,
        CilOpCodes.Ldfld,
        CilOpCodes.Callvirt,
        CilOpCodes.Stloc_S,
        CilOpCodes.Ldarg_0,
        CilOpCodes.Ldfld,
        CilOpCodes.Callvirt,
        CilOpCodes.Call,
        CilOpCodes.Stloc_S,
        CilOpCodes.Ldarg_0,
        CilOpCodes.Ldfld,
        CilOpCodes.Callvirt,
        CilOpCodes.Ldnull,
        CilOpCodes.Callvirt,
        CilOpCodes.Castclass,
        CilOpCodes.Ldloc_S,
        CilOpCodes.Ldloc_S,
        CilOpCodes.Callvirt,
        CilOpCodes.Ldloc_S,
        CilOpCodes.Callvirt,
        CilOpCodes.Ldflda,
        CilOpCodes.Ldfld,
        CilOpCodes.Callvirt,
        CilOpCodes.Ret
    };

    public CilOpCode CilOpCode => CilOpCodes.Stelem;

    public bool Verify(EzirizHandler handler) => true;
}

#endregion

#region Ldelem_I

internal record LdelemI : IOpCodePattern
{
    public IList<CilOpCode> Pattern => new List<CilOpCode>
    {
        CilOpCodes.Ldarg_0,
        CilOpCodes.Ldfld,
        CilOpCodes.Callvirt,
        CilOpCodes.Call,
        CilOpCodes.Stloc_S,
        CilOpCodes.Ldarg_0,
        CilOpCodes.Ldfld,
        CilOpCodes.Callvirt,
        CilOpCodes.Ldnull,
        CilOpCodes.Callvirt,
        CilOpCodes.Castclass,
        CilOpCodes.Ldloc_S,
        CilOpCodes.Callvirt,
        CilOpCodes.Ldflda,
        CilOpCodes.Ldfld,
        CilOpCodes.Callvirt,
        CilOpCodes.Stloc_S,
        CilOpCodes.Ldarg_0,
        CilOpCodes.Ldfld,
        CilOpCodes.Ldtoken,
        CilOpCodes.Call,
        CilOpCodes.Ldloc_S,
        CilOpCodes.Call,
        CilOpCodes.Callvirt,
        CilOpCodes.Ret
    };

    public CilOpCode CilOpCode { get; set; } = CilOpCodes.Ldelem_I4;

    public bool Verify(EzirizHandler handler)
    {
        if (handler.Instructions[^6].Operand is ITypeDefOrRef typeDef)
        {
            switch (typeDef.FullName)
            {
                case "System.Byte":
                    CilOpCode = CilOpCodes.Ldelem_I1;
                    return true;
                case "System.SByte":
                    CilOpCode = CilOpCodes.Ldelem_U1;
                    return true;
                case "System.Int16":
                    CilOpCode = CilOpCodes.Ldelem_I2;
                    return true;
                case "System.UInt16":
                    CilOpCode = CilOpCodes.Ldelem_U2;
                    return true;
                case "System.Int32":
                    CilOpCode = CilOpCodes.Ldelem_I4;
                    return true;
                case "System.UInt32":
                    CilOpCode = CilOpCodes.Ldelem_U4;
                    return true;
                case "System.Int64":
                    CilOpCode = CilOpCodes.Ldelem_I8;
                    return true;
                case "System.IntPtr":
                    CilOpCode = CilOpCodes.Ldelem_I;
                    return true;
                case "System.Single":
                    CilOpCode = CilOpCodes.Ldelem_R4;
                    return true;
                case "System.Double":
                    CilOpCode = CilOpCodes.Ldelem_R8;
                    return true;
            }
        }
        return false;
    }

    public bool AllowMultiple => true;
}

#endregion
