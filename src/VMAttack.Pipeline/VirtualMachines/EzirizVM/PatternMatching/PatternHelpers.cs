using System.Collections.Generic;
using System.Linq;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Serialized;
using VMAttack.Pipeline.VirtualMachines.EzirizVM.Interfaces;

namespace VMAttack.Pipeline.VirtualMachines.EzirizVM.PatternMatching;

public static class PatternHelpers
{
    public static bool FindPatternInOverrides(this SerializedMethodDefinition? virtualMethod, IPattern pattern)
    {
        if (virtualMethod is not { IsVirtual: true, IsAbstract: true })
            return false;

        if (virtualMethod.Module is null)
            return false;

        var overwrites = virtualMethod.GetOverwrites();

        return overwrites.Count(vMethod => PatternMatcher.GetAllMatchingInstructions(pattern, vMethod.CilMethodBody.Instructions).Count == 1) > 0;
    }

    public static List<MethodDefinition> GetPatternInOverrides(this SerializedMethodDefinition? virtualMethod, IPattern pattern)
    {
        var overwrites = new List<MethodDefinition>();

        if (virtualMethod is not { IsVirtual: true, IsAbstract: true })
            return overwrites;

        if (virtualMethod.Module is null)
            return overwrites;

        overwrites.AddRange(GetOverwrites(virtualMethod).Where(vMethod => PatternMatcher.GetAllMatchingInstructions(pattern, vMethod.CilMethodBody.Instructions).Count == 1));

        return overwrites;
    }

    public static List<MethodDefinition> GetOverwrites(this SerializedMethodDefinition? virtualMethod)
    {
        var overwrites = new List<MethodDefinition>();

        foreach (var t in virtualMethod.Module.GetAllTypes())
        foreach (var vMethod in t.Methods.Where(x => x.IsVirtual && x.HasMethodBody && x.Name == virtualMethod.Name))
        {
            if (vMethod.CilMethodBody is null)
                continue;

            overwrites.Add(vMethod);
        }

        return overwrites;
    }
}
